//! Запуск без терминального интерфейса.
//!
//! # Зачем
//!
//! TUI полезен, когда за программой смотрят. Но смотрят не всегда: её
//! запускают из systemd, гоняют в контейнере, дёргают из скрипта, а на
//! Android терминала нет вовсе. Во всех этих случаях альтернативного
//! запуска не было — только TUI, который без TTY просто падает с
//! «No such device or address».
//!
//! Здесь тот же набор слушателей, но вместо панели логов — обычный вывод
//! в stdout, который можно перенаправить в файл или отдать journald.
//!
//! # Чего здесь нет
//!
//! Управления. Диагностику не запустить, конфиг не поправить, прокси не
//! перезапустить — всё это интерактивные действия, и подменять их флагами
//! значило бы выращивать второй интерфейс. Нужна диагностика — есть
//! `--diagnose-only`; нужна правка конфига — это текстовый файл.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::observability::logging::{self as log, LogLevel, LogPayload};
use crate::Startup;

/// Язык сообщений в headless-режиме.
///
/// Берётся из `NET_SURGEON_LANG`, по умолчанию русский — как и в TUI.
/// Переключать на лету некому, поэтому значение читается один раз.
fn language() -> String {
    crate::default_language().to_string()
}

fn level_marker(level: LogLevel) -> String {
    use crate::observability::glyph;
    match level {
        LogLevel::Info => "[i]".to_string(),
        LogLevel::Success => format!("[{}]", glyph::OK),
        LogLevel::Warning => "[!]".to_string(),
        LogLevel::Error => format!("[{}]", glyph::ERROR),
    }
}

fn render(lang: &str, payload: &LogPayload) -> String {
    use crate::observability::i18n;

    match payload {
        LogPayload::Plain(s) => s.clone(),
        LogPayload::Translated { key, args } => i18n::translate(lang, key, args),
        LogPayload::NestedTranslated { key, nested_arg, nested_key, args } => {
            i18n::translate_nested(lang, key, nested_arg, nested_key, args)
        }
    }
}

/// Поднимает слушатели и печатает логи, пока не придёт Ctrl-C.
pub async fn run(diagnostics_only: bool, startup: Startup) {
    let lang = language();
    let (log_tx, mut log_rx) = log::channel();

    // Резолвер поднят раньше — канал логов подключается отдельно, иначе
    // откат DoH на системный DNS был бы не виден.
    crate::dns::resolver::attach_logger(log_tx.clone());

    if let Some(reason) = &startup.domains_error {
        eprintln!(
            "[{}] {}",
            crate::observability::glyph::ERROR,
            render(
                &lang,
                &LogPayload::Translated {
                    key: "startup.domains_missing".into(),
                    args: vec![("error".into(), reason.clone())],
                },
            )
        );
    } else if startup.domains.is_empty() {
        eprintln!(
            "[!] {}",
            render(&lang, &LogPayload::Translated { key: "startup.domains_empty".into(), args: vec![] })
        );
    }

    for update in &startup.list_updates {
        let (level, payload) = update.log_message();
        eprintln!("{} {}", level_marker(level), render(&lang, &payload));
    }

    let token = CancellationToken::new();

    if diagnostics_only || startup.config.diagnostics_only {
        // Режим «только диагностика»: слушатели не поднимаются, менять
        // трафик нечем. Прогон здесь не запускается — им управляет TUI,
        // а без него единственное осмысленное поведение это сказать,
        // что делать нечего, и выйти.
        println!(
            "[!] {}",
            render(&lang, &LogPayload::Translated { key: "log.diagnostics_only_mode".into(), args: vec![] })
        );
        return;
    }

    {
        let token = token.clone();
        let log_tx = log_tx.clone();
        let config = Arc::clone(&startup.config);
        let domains = Arc::clone(&startup.domains);
        let metrics = Arc::clone(&startup.metrics);
        let ip_cache = Arc::clone(&startup.ip_cache);
        let strategies = Arc::clone(&startup.strategies);
        tokio::spawn(async move {
            crate::proxy::run_all(config, domains, log_tx, metrics, token, ip_cache, strategies).await;
        });
    }

    // Сброс накопленных исходов на диск по таймеру — ровно как в TUI.
    // Без него live_ok/live_fail не пережили бы завершение процесса.
    let flush = {
        let strategies = Arc::clone(&startup.strategies);
        let token = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        if strategies.is_dirty()
                            && let Err(e) = strategies.save()
                        {
                            eprintln!("[{}] {}", crate::observability::glyph::ERROR, crate::observability::i18n::translate(crate::default_language(), "startup.strategies_save_failed", &[("error".into(), e.to_string())]));
                        }
                    }
                }
            }
        })
    };

    // SIGTERM шлёт systemd при остановке службы и `kill` по умолчанию. Раньше
    // ловился только Ctrl-C, и такое завершение убивало процесс без
    // сохранения strategies.txt.
    let mut terminate = terminate_signal();

    loop {
        tokio::select! {
            _ = wait_terminate(&mut terminate) => {
                println!("[i] {}", crate::observability::i18n::translate(&lang, "startup.sigterm", &[]));
                token.cancel();
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("[i] {}", crate::observability::i18n::translate(&lang, "startup.exiting", &[]));
                token.cancel();
                break;
            }
            msg = log_rx.recv() => {
                let Some(msg) = msg else { break };

                // Маркер завершения прогона диагностики — служебный,
                // показывать его незачем.
                if let LogPayload::Plain(text) = &msg.payload
                    && text == "__DIAGNOSTICS_DONE__"
                {
                    continue;
                }

                let time = chrono::Local::now().format("%H:%M:%S");
                println!("{} {} {}", level_marker(msg.level), time, render(&lang, &msg.payload));
            }
        }
    }

    flush.abort();

    if startup.strategies.is_dirty()
        && let Err(e) = startup.strategies.save()
    {
        eprintln!("[{}] {}", crate::observability::glyph::ERROR, crate::observability::i18n::translate(&lang, "startup.strategies_save_failed", &[("error".into(), e.to_string())]));
    }
}

#[cfg(unix)]
type TerminateSignal = Option<tokio::signal::unix::Signal>;
/// В Windows сигналов нет; ближе всего к SIGTERM закрытие окна консоли.
/// После него система даёт процессу несколько секунд, и этого хватает,
/// чтобы сохранить strategies.txt.
#[cfg(windows)]
type TerminateSignal = Option<tokio::signal::windows::CtrlClose>;

#[cfg(unix)]
fn terminate_signal() -> TerminateSignal {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok()
}

#[cfg(windows)]
fn terminate_signal() -> TerminateSignal {
    tokio::signal::windows::ctrl_close().ok()
}

/// Ждёт SIGTERM (в Windows — закрытия окна). Если подписаться не удалось —
/// не завершается никогда, и остаётся Ctrl-C.
async fn wait_terminate(signal: &mut TerminateSignal) {
    match signal {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending().await,
    }
}
