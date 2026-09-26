//! Мост между ядром net_surgeon и приложением на Android.
//!
//! # Как идёт трафик
//!
//! Android не даёт обычному приложению ни iptables, ни сырых сокетов. Зато
//! есть `VpnService`: система заворачивает весь трафик телефона в TUN-
//! интерфейс и отдаёт приложению его дескриптор. Дальше:
//!
//! ```text
//! приложения телефона → TUN → tun2proxy → SOCKS5 ядра → интернет
//! ```
//!
//! tun2proxy собирает из IP-пакетов TCP-соединения и UDP-датаграммы и
//! отдаёт их нашему же SOCKS5-серверу на 127.0.0.1. Там работает всё, что и
//! на компьютере: выбор техники обхода, диагностика, DoH, блокировка трекеров.
//!
//! Петли нет, потому что Kotlin-сторона исключает само приложение из VPN
//! (`addDisallowedApplication`): сокеты ядра идут в сеть напрямую.
//!
//! # DNS
//!
//! tun2proxy в режиме virtual DNS отвечает на запросы выдуманными адресами
//! из 198.18.0.0/15 и запоминает, какому имени какой выдал. Когда приложение
//! подключается к такому адресу, в SOCKS5 уходит уже ИМЯ, а не адрес. Ядро
//! резолвит его своим DoH, и провайдер не видит ни запроса, ни ответа, а
//! решение об обходе принимается по имени ещё до ClientHello.
//!
//! # Почему runtime один на весь процесс
//!
//! Резолвер DoH и канал логов в ядре — синглтоны, которые ставятся один раз
//! (`OnceLock`). VPN же включают и выключают много раз, не перезапуская
//! приложение. Если бы каждый запуск строил свой runtime и свой канал, после
//! первого выключения логи шли бы в закрытый канал. Поэтому runtime, канал и
//! сборщик логов живут весь процесс, а «вкл/выкл» — это запуск задач и отмена
//! их токена.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use net_surgeon::observability::i18n;
use net_surgeon::observability::logging::{self as nlog, LogLevel, LogPayload, LogSender};

/// Сколько последних строк лога держать для экрана. Больше телефону
/// показывать незачем, а память не бесконечна.
const LOG_CAPACITY: usize = 500;

/// Выдуманные адреса virtual DNS. Тот же диапазон, что по умолчанию у
/// tun2proxy; Kotlin-сторона направляет его в TUN.
const VIRTUAL_DNS_POOL: &str = "198.18.0.0/15";

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static LOG_TX: OnceLock<LogSender> = OnceLock::new();
static LOGS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
static LANG: Mutex<String> = Mutex::new(String::new());
static RUNNING: Mutex<Option<CancellationToken>> = Mutex::new(None);

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("net_surgeon")
            .build()
            .expect("tokio runtime")
    })
}

fn push_line(line: String) {
    // Дублируем в logcat: `adb logcat -s net_surgeon` при отладке.
    log::info!("{line}");
    if let Ok(mut logs) = LOGS.lock() {
        if logs.len() >= LOG_CAPACITY {
            logs.pop_front();
        }
        logs.push_back(line);
    }
}

/// Строка из словаря ядра на языке, выбранном при запуске.
fn tr(key: &str, args: &[(&str, String)]) -> String {
    let lang = LANG.lock().map(|l| l.clone()).unwrap_or_default();
    let args: Vec<(String, String)> = args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    i18n::translate(&lang, key, &args)
}

fn marker(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Info => "·",
        LogLevel::Success => "✓",
        LogLevel::Warning => "!",
        LogLevel::Error => "✗",
    }
}

fn render(lang: &str, payload: &LogPayload) -> String {
    match payload {
        LogPayload::Plain(s) => s.clone(),
        LogPayload::Translated { key, args } => i18n::translate(lang, key, args),
        LogPayload::NestedTranslated { key, nested_arg, nested_key, args } => {
            i18n::translate_nested(lang, key, nested_arg, nested_key, args)
        }
    }
}

/// Канал логов ядра и задача, которая перекладывает сообщения в буфер
/// для экрана. Создаются один раз.
fn log_tx() -> &'static LogSender {
    LOG_TX.get_or_init(|| {
        let (tx, mut rx) = nlog::channel();
        net_surgeon::dns::resolver::attach_logger(tx.clone());
        runtime().spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let LogPayload::Plain(text) = &msg.payload
                    && text == "__DIAGNOSTICS_DONE__"
                {
                    continue;
                }
                let lang = LANG.lock().map(|l| l.clone()).unwrap_or_default();
                let time = chrono::Local::now().format("%H:%M:%S");
                push_line(format!("{} {} {}", time, marker(msg.level), render(&lang, &msg.payload)));
            }
        });
        tx
    })
}

/// Поднимает ядро и tun2proxy поверх дескриптора TUN. `None` — запущено,
/// иначе текст ошибки для экрана.
fn start(tun_fd: i32, data_dir: String, lang: String) -> Option<String> {
    if let Ok(mut l) = LANG.lock() {
        *l = lang.clone();
    }
    let mut running = RUNNING.lock().ok()?;
    if running.is_some() {
        return Some(tr("startup.already_running", &[]));
    }

    // Каталог данных ядро вычисляет один раз, при первом обращении, и эта
    // переменная — его первый источник. Ставится до bootstrap.
    //
    // SAFETY: другие потоки окружение не читают: runtime ещё не запускал
    // задач ядра, а set_var до первого старта выполняется один раз.
    if std::env::var_os("NET_SURGEON_DIR").is_none() {
        unsafe { std::env::set_var("NET_SURGEON_DIR", &data_dir) };
    }
    net_surgeon::set_locale(&lang);

    let startup = match net_surgeon::bootstrap() {
        Ok(s) => s,
        Err(e) => return Some(e),
    };
    let log_tx = log_tx().clone();

    if let Some(reason) = &startup.domains_error {
        nlog::log_t(&log_tx, LogLevel::Error, "startup.domains_missing", vec![("error", reason.clone())]);
    }
    for update in &startup.list_updates {
        let (level, payload) = update.log_message();
        let _ = log_tx.send(nlog::LogMessage { level, payload });
    }

    let socks = format!("socks5://127.0.0.1:{}", startup.config.socks5_port);
    let proxy = match tun2proxy::ArgProxy::try_from(socks.as_str()) {
        Ok(p) => p,
        Err(e) => return Some(tr("startup.bad_socks_addr", &[("error", e.to_string())])),
    };
    let pool = match VIRTUAL_DNS_POOL.parse() {
        Ok(p) => p,
        Err(e) => return Some(tr("startup.bad_dns_pool", &[("error", format!("{e:?}"))])),
    };
    let mut args = tun2proxy::Args::default();
    args.proxy(proxy)
        .tun_fd(Some(tun_fd))
        // Дескриптор отдан нам Kotlin-стороной через detachFd(): закрывать
        // его теперь наша забота, иначе он утечёт при каждом выключении.
        .close_fd_on_drop(true)
        .dns(tun2proxy::ArgDns::Virtual);
    args.virtual_dns_pool = pool;

    let token = CancellationToken::new();
    let rt = runtime();

    {
        let token = token.clone();
        let log_tx = log_tx.clone();
        let config = Arc::clone(&startup.config);
        let domains = Arc::clone(&startup.domains);
        let metrics = Arc::clone(&startup.metrics);
        let ip_cache = Arc::clone(&startup.ip_cache);
        let strategies = Arc::clone(&startup.strategies);
        rt.spawn(async move {
            net_surgeon::proxy::run_all(config, domains, log_tx, metrics, token, ip_cache, strategies).await;
        });
    }

    {
        let token = token.clone();
        let mtu = args.mtu;
        rt.spawn(async move {
            // Ядру нужно мгновение, чтобы поднять SOCKS5: без паузы первые
            // соединения tun2proxy получили бы отказ.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            match tun2proxy::general_run_async(args, mtu, false, token).await {
                Ok(_) => push_line(tr("startup.tun_stopped", &[])),
                Err(e) => push_line(format!("✗ {}", tr("startup.tun_error", &[("error", e.to_string())]))),
            }
        });
    }

    // Стратегии на диск — по таймеру и при остановке, как в headless-режиме.
    {
        let token = token.clone();
        let strategies = Arc::clone(&startup.strategies);
        rt.spawn(async move {
            loop {
                let stopped = tokio::select! {
                    _ = token.cancelled() => true,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => false,
                };
                if strategies.is_dirty()
                    && let Err(e) = strategies.save()
                {
                    push_line(format!("✗ strategies.txt: {e}"));
                }
                if stopped {
                    break;
                }
            }
        });
    }

    nlog::log_t(&log_tx, LogLevel::Success, "startup.proxy_started", vec![]);
    *running = Some(token);
    None
}

fn stop() {
    if let Ok(mut running) = RUNNING.lock()
        && let Some(token) = running.take()
    {
        token.cancel();
    }
}

fn java_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(Into::into).unwrap_or_default()
}

// --- JNI: класс io.github.netsurgeon.NativeBridge ---------------------------

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_netsurgeon_NativeBridge_start<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    tun_fd: jint,
    data_dir: JString<'l>,
    lang: JString<'l>,
) -> jstring {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("net_surgeon")
            .with_max_level(log::LevelFilter::Info),
    );
    let data_dir = java_string(&mut env, &data_dir);
    let lang = java_string(&mut env, &lang);

    match start(tun_fd, data_dir, lang) {
        None => std::ptr::null_mut(),
        Some(err) => {
            // До tun2proxy дескриптор не дошёл, а Kotlin его уже отдал
            // (detachFd): закрыть больше некому. Открытый TUN держал бы VPN
            // «включённым» без единого читателя, и сеть телефона встала бы.
            unsafe { libc::close(tun_fd) };
            push_line(format!("✗ {err}"));
            env.new_string(err).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_netsurgeon_NativeBridge_stop<'l>(_env: JNIEnv<'l>, _class: JClass<'l>) {
    stop();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_netsurgeon_NativeBridge_isRunning<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jboolean {
    match RUNNING.lock() {
        Ok(r) if r.is_some() => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// Все накопленные строки лога, по одной на строку. Буфер не очищается:
/// экран при каждом открытии показывает хвост целиком.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_netsurgeon_NativeBridge_logs<'l>(
    env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jstring {
    let text = LOGS
        .lock()
        .map(|l| l.iter().cloned().collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    env.new_string(text).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}
