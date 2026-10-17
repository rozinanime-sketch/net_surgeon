//! Правила прозрачного режима, которые снимает само ядро.
//!
//! # Зачем
//!
//! Раньше перехват ставил `run.sh` через `sudo iptables`, а правило живёт
//! дольше процесса. Прокси завершился, правило осталось, и весь HTTPS
//! машины уходит на порт, где никто не слушает. Против этого в `run.sh`
//! выросли trap на пять сигналов, сторож от root и «тёплый» sudo, и всё
//! равно хватало одного истёкшего пароля sudo на выходе, чтобы сеть лежала
//! до перезагрузки.
//!
//! # Как
//!
//! Таблица nftables с флагом `owner` принадлежит сокету netlink, который
//! её создал, и ядро удаляет её, как только сокет закрыт. Сокет держит
//! дочерний `nft -i`: мы пишем ему команды в stdin и не закрываем его до
//! выхода. Умер прокси как угодно, хоть `kill -9`, хоть OOM — у `nft`
//! закрывается stdin (и приходит PDEATHSIG), он выходит, таблица исчезает.
//! Снимать при выходе нечего, поэтому и sudo на выходе не нужен.
//!
//! Права на это у процесса свои: `run.sh` один раз после сборки выдаёт
//! бинарю `cap_net_admin` и группу `nsproxy` с битом setgid. Дочернему
//! `nft` право передаётся как ambient-capability — только ему и `ip`.
//!
//! Свой трафик прокси отличается от чужого по группе: исходящие соединения
//! самого прокси ушли бы обратно в перехват. По пользователю разделить
//! нельзя — браузер работает под тем же. Подробнее — в `setup-transparent.sh`.
//!
//! Переживает выход только маршрутная пара для QUIC (`ip rule` + `ip route`
//! в таблице 100): у маршрутов владельцев нет. Без правила, которое ставит
//! метку, она ни на что не влияет, а при следующем запуске и в
//! `./run.sh off` снимается.

use std::io::{self, Write};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::Duration;

/// Имя таблицы. Одно на машину: второй экземпляр прокси не сможет её
/// создать и честно откажется стартовать, а не удвоит перехват.
pub const TABLE: &str = "net_surgeon";

/// Метка и таблица маршрутизации для QUIC — те же, что в `run.sh`, чтобы
/// `./run.sh off` снимал и их.
const MARK: u32 = 0x1;
const RT_TABLE: u32 = 100;

const CAP_NET_ADMIN: u32 = 12;

/// Пакетный режим: номер очереди NFQUEUE (то же значение — `nfqueue::QUEUE_NUM`).
/// fwmark'и переотправки и проб берутся из `crate::bypass::packet_mode`.
const NFQ_QUEUE: u16 = 0;

/// Что включить.
pub struct Plan {
    /// Группа, трафик которой не перехватывается, — группа самого прокси.
    pub gid: u32,
    /// Порт прозрачного режима (TCP и QUIC).
    pub port: u16,
    /// Порт DoH-релея для перехвата DNS, 0 — не перехватывать.
    pub dns_port: u16,
    /// Перехватывать ли QUIC (нужна маршрутная пара).
    pub quic: bool,
    /// Перехватывать ли и UDP звонков (`session::CALL_PORTS` и сети
    /// Telegram). Идёт той же дорогой, что QUIC, и без неё не включается.
    pub calls: bool,
    /// Пакетный режим: TCP/443 не заворачивается на слушатель, а уходит в
    /// очередь NFQUEUE (`crate::nfqueue`). QUIC и DNS — по-прежнему.
    pub packet: bool,
    /// Узнавать ClientHello по началу данных (`@ih`, nftables ≥ 1.0.1), а не
    /// по флагам TCP. Старый nft этого не умеет — тогда прежнее правило.
    pub hello_by_payload: bool,
}

/// ClientHello по началу данных: запись Handshake (0x16 0x03) с сообщением
/// ClientHello (тип 1 в шестом байте) — как фильтр WinDivert. Только первый
/// сегмент ClientHello и его повторы, а не каждый сегмент данных.
///
/// Раньше в очередь шли пакеты с PSH+ACK. ClientHello, разрезанный на
/// несколько сегментов (постквантовый, ~1,8 КБ, без GSO на интерфейсе),
/// несёт PSH только в последнем, и первый — с SNI — уходил мимо очереди
/// необработанным. А любой другой сегмент с PSH (загрузки, HTTP/2,
/// WebSocket) всё время жизни соединения гонялся через userspace впустую.
const HELLO_BY_PAYLOAD: &str = "tcp dport 443 @ih,0,16 0x1603 @ih,40,8 0x01";
/// Прежний признак для nft без `@ih`.
const HELLO_BY_FLAGS: &str = "tcp dport 443 tcp flags & (fin | syn | rst | psh | ack) == (psh | ack)";

/// Команды для `nft`, по одной на строку: так их понимает и `nft -f`,
/// и `nft -i`.
pub fn ruleset(plan: &Plan) -> String {
    let t = format!("inet {TABLE}");
    let Plan { gid, port, dns_port, quic, calls, packet, hello_by_payload } = *plan;
    let mut s = String::new();
    let mut add = |line: String| {
        s.push_str(&line);
        s.push('\n');
    };

    add(format!("add table {t} {{ flags owner; }}"));

    // TCP/443 и DNS: как REDIRECT в iptables, адрес назначения прокси
    // достаёт из conntrack (SO_ORIGINAL_DST). Семейство inet заворачивает
    // и IPv6 — на [::1], где прокси держит второй слушатель.
    add(format!("add chain {t} nat_out {{ type nat hook output priority -100; }}"));
    add(format!("add rule {t} nat_out meta skgid {gid} return"));
    if packet {
        // Пакетный режим: TCP/443 в очередь NFQUEUE вместо разворота на
        // слушатель. Только IPv4 (raw-сокет переотправки отдаёт IP-заголовок
        // сам лишь для v4) и только ClientHello (см. HELLO_BY_PAYLOAD): SYN
        // занял бы метку/поток раньше самого ClientHello.
        //
        // Флаг `bypass` — предохранитель «нет читателя → пропустить»: если
        // процесс не смог занять очередь (нет CAP_NET_RAW, упал), ядро по
        // умолчанию ДРОПает попавшие в правило пакеты, и весь HTTPS ложится.
        // С bypass такой пакет просто идёт дальше без обхода — связь цела.
        let reinject = crate::bypass::packet_mode::REINJECT_FWMARK;
        let probe = crate::bypass::packet_mode::PROBE_FWMARK;
        let hello = format!(
            "meta nfproto ipv4 {}",
            if hello_by_payload { HELLO_BY_PAYLOAD } else { HELLO_BY_FLAGS }
        );
        add(format!("add chain {t} queue_out {{ type filter hook output priority 0; }}"));
        // Свои переотправленные сегменты — мимо очереди.
        add(format!("add rule {t} queue_out meta mark {reinject:#x} return"));
        // Пробы диагностики: в очередь, несмотря на исключение группы прокси ниже.
        add(format!("add rule {t} queue_out meta mark {probe:#x} {hello} queue num {NFQ_QUEUE} bypass"));
        // Остальной трафик самой программы (DoH, ретранслятор) не трогаем.
        add(format!("add rule {t} queue_out meta skgid {gid} return"));
        // ClientHello приложений.
        add(format!("add rule {t} queue_out {hello} queue num {NFQ_QUEUE} bypass"));
        // IPv6 очередь не переотправит — его на слушатель, как в сокетном
        // режиме. Раньше IPv6 HTTPS в пакетном режиме шёл без обхода вовсе.
        add(format!("add rule {t} nat_out meta nfproto ipv6 tcp dport 443 redirect to :{port}"));
    } else {
        add(format!("add rule {t} nat_out tcp dport 443 redirect to :{port}"));
    }
    if dns_port > 0 {
        // Локальные резолверы (systemd-resolved на 127.0.0.53) не трогаем:
        // наружу они ходят на настоящий адрес, там их и поймает правило.
        // IPv6-резолвер (от провайдера по RA) — тоже в релей: он слушает и
        // [::1]. DNS по TCP не заворачивается: релей принимает только UDP.
        add(format!(
            "add rule {t} nat_out ip daddr != 127.0.0.0/8 udp dport 53 redirect to :{dns_port}"
        ));
        add(format!(
            "add rule {t} nat_out ip6 daddr != ::1 udp dport 53 redirect to :{dns_port}"
        ));
    }

    // QUIC: TPROXY работает только в PREROUTING, а наш трафик рождается
    // локально. Поэтому метка в OUTPUT, маршрутная пара заворачивает
    // помеченное на lo, и в PREROUTING его подхватывает tproxy. Механика
    // подробно — в run.sh.
    if quic {
        // Метка — только пакету без своей (чужие fwmark не затираем) и от
        // сокета пользовательского процесса. `meta skgid` у сокетов ядра
        // (WireGuard) не определён, и условие с ним для них ложно: раньше
        // рукопожатие WireGuard на 51820 попадало под порты звонков, теряло
        // свою метку и уходило по кругу через lo — VPN ложился.
        let ours = format!("meta mark 0 meta skgid != {gid}");
        add(format!("add chain {t} mark_out {{ type route hook output priority mangle; }}"));
        add(format!("add rule {t} mark_out meta skgid {gid} return"));
        add(format!("add rule {t} mark_out {ours} meta nfproto ipv4 udp dport 443 meta mark set {MARK:#x}"));
        // Звонки — той же дорогой: прозрачный UDP-слушатель сам решит,
        // менять ли им порт (session::is_call_flow, session::Hop).
        if calls {
            let ports = crate::proxy::udp::session::CALL_PORTS
                .iter()
                .map(|(a, b)| format!("{a}-{b}"))
                .collect::<Vec<_>>()
                .join(", ");
            let local = crate::proxy::udp::session::LOCAL_NETS_V4
                .iter()
                .map(|(ip, bits)| format!("{}/{bits}", std::net::Ipv4Addr::from(*ip)))
                .collect::<Vec<_>>()
                .join(", ");
            add(format!(
                "add rule {t} mark_out {ours} ip daddr != {{ {local} }} udp dport {{ {ports} }} meta mark set {MARK:#x}"
            ));
            let nets = crate::proxy::telegram::networks_v4()
                .map(|(ip, bits)| format!("{ip}/{bits}"))
                .collect::<Vec<_>>()
                .join(", ");
            // DNS к ним не трогаем: он уже заворачивается в DoH-релей.
            add(format!(
                "add rule {t} mark_out {ours} ip daddr {{ {nets} }} udp dport != 53 meta mark set {MARK:#x}"
            ));
        }
        add(format!("add chain {t} tproxy_pre {{ type filter hook prerouting priority mangle; }}"));
        // По метке, а не по порту: помечено ровно то, что выбрано выше.
        add(format!(
            "add rule {t} tproxy_pre iifname \"lo\" meta nfproto ipv4 meta l4proto udp \
             meta mark {MARK:#x} tproxy ip to 127.0.0.1:{port} accept"
        ));
    }
    s
}

/// Держатель таблицы: пока жив дочерний `nft` и открыт его stdin,
/// правила стоят.
struct Held {
    child: Child,
    stdin: ChildStdin,
    routing: bool,
}

static HELD: Mutex<Option<Held>> = Mutex::new(None);

/// Отравленный замок не повод терять держателя: без него таблица исчезла
/// бы, а пользователь видел бы «перехват включён».
fn held() -> std::sync::MutexGuard<'static, Option<Held>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Маршрутная пара, снимаемая при выходе из `install` с ошибкой, — на любом
/// пути, в том числе через `?`. Раньше снятие было вписано вручную в три
/// места, а на трёх других пара оставалась висеть.
struct RoutingGuard {
    armed: bool,
}

impl RoutingGuard {
    /// Установка удалась — пара остаётся и снимется в `release`.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for RoutingGuard {
    fn drop(&mut self) {
        if self.armed {
            del_routing();
        }
    }
}

/// Остановить `nft` и дождаться его, чтобы не оставлять зомби.
fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Ставит перехват. Возвращает, что включено, для сообщения пользователю.
///
/// Звать из потока, который живёт до конца программы, — из главного.
/// `nft` умирает вместе с потоком, который его запустил (PDEATHSIG
/// привязан к потоку, а не к процессу), и с ним — таблица. Из пула
/// `spawn_blocking` правила пропадали через ~10 с, когда tokio убирал
/// простаивающий поток.
pub fn install(port: u16, dns_port: u16, calls: bool, packet: bool) -> Result<String, String> {
    if port == 0 {
        return Err(rust_i18n::t!("fw.no_port").into_owned());
    }

    // Группа прокси должна отличаться от обычной группы пользователя:
    // иначе исключение «свой трафик» выкинуло бы из перехвата всё, что
    // пользователь запустил, и перехват молча ничего бы не делал.
    let (gid, egid) = unsafe { (libc::getgid(), libc::getegid()) };
    if gid == egid {
        return Err(rust_i18n::t!("fw.no_group").into_owned());
    }

    if held().is_some() {
        return Err(rust_i18n::t!("fw.already_on").into_owned());
    }

    // Проверка раньше, чем что-то менять: без права ни nft, ни ip ничего
    // не сделают, а их ошибки («Operation not permitted») не объясняют, что
    // дело в пересобранном бинаре, с которого слетели полномочия.
    let check = run_with_cap("nft", &["list", "tables"]).map_err(|e| nft_missing(&e))?;
    if !check.status.success() {
        return Err(rust_i18n::t!("fw.no_cap", error = stderr_line(&check)).into_owned());
    }

    // До любых изменений: иначе второй экземпляр, прежде чем получить
    // отказ от nft, снял бы маршрутную пару первого и сломал ему QUIC.
    if table_present() {
        return Err(rust_i18n::t!("fw.taken").into_owned());
    }

    let routing = add_routing();
    let guard = RoutingGuard { armed: routing };
    let plan = |hello_by_payload| Plan { gid: egid, port, dns_port, quic: routing, calls, packet, hello_by_payload };

    // `nft -i` не сообщает об ошибках кодом выхода — он продолжает читать
    // stdin. Поэтому сначала пробный прогон с тем же текстом. Старый nft не
    // знает `@ih` — тогда правило пакетного режима по флагам TCP.
    let check = |rules: &str| run_with_cap_stdin("nft", &["-c", "-f", "-"], rules).map_err(|e| nft_missing(&e));
    let mut rules = ruleset(&plan(true));
    let mut dry = check(&rules)?;
    if !dry.status.success() && packet {
        rules = ruleset(&plan(false));
        dry = check(&rules)?;
    }
    if !dry.status.success() {
        return Err(rust_i18n::t!("fw.rejected", error = stderr_line(&dry)).into_owned());
    }

    let mut child = spawn_with_cap("nft", &["-i"])
        .map_err(|e| nft_missing(&e))?;
    let Some(mut stdin) = child.stdin.take() else {
        stop(child);
        return Err(rust_i18n::t!("fw.no_stdin").into_owned());
    };
    if let Err(e) = stdin.write_all(rules.as_bytes()).and_then(|_| stdin.flush()) {
        stop(child);
        return Err(rust_i18n::t!("fw.send_failed", error = e).into_owned());
    }

    // Команды применяются асинхронно, пока nft читает stdin: ждём таблицу.
    let mut present = false;
    for _ in 0..20 {
        if table_present() {
            present = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !present {
        stop(child);
        return Err(rust_i18n::t!("fw.table_missing").into_owned());
    }

    *held() = Some(Held { child, stdin, routing });
    guard.keep();

    let mut what = vec!["TCP/443".to_string()];
    if routing {
        what.push("QUIC".into());
        if calls {
            what.push(rust_i18n::t!("fw.calls").into_owned());
        }
    }
    if dns_port > 0 {
        what.push("DNS".into());
    }
    Ok(rust_i18n::t!("fw.installed", rules = what.join(", ")).into_owned())
}

/// Штатное снятие. Таблицу ядро убрало бы и само, а маршрутную пару —
/// нет, поэтому зовётся при выходе из `main`.
pub fn release() {
    let taken = held().take();
    if let Some(mut h) = taken {
        drop(h.stdin);
        let _ = h.child.wait();
        if h.routing {
            del_routing();
        }
    }
}

fn table_present() -> bool {
    run_with_cap("nft", &["list", "table", "inet", TABLE])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Маршрутная пара для QUIC. Остатки прошлого запуска сначала снимаются,
/// иначе копии копились бы.
fn add_routing() -> bool {
    del_routing();
    let mark = format!("{MARK:#x}");
    let table = RT_TABLE.to_string();
    let rule = run_with_cap("ip", &["rule", "add", "fwmark", &mark, "lookup", &table]);
    let route = run_with_cap("ip", &["route", "add", "local", "default", "dev", "lo", "table", &table]);
    let ok = matches!((&rule, &route), (Ok(r), Ok(t)) if r.status.success() && t.status.success());
    if !ok {
        del_routing();
    }
    ok
}

fn del_routing() {
    let mark = format!("{MARK:#x}");
    let table = RT_TABLE.to_string();
    // Предел — на случай, если `del` почему-то «успешен», а правило стоит.
    for _ in 0..16 {
        match run_with_cap("ip", &["rule", "del", "fwmark", &mark, "lookup", &table]) {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }
    for _ in 0..16 {
        match run_with_cap("ip", &["route", "del", "local", "default", "dev", "lo", "table", &table]) {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }
}

fn nft_missing(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        rust_i18n::t!("fw.no_nft").into_owned()
    } else {
        rust_i18n::t!("fw.nft_start_failed", error = e).into_owned()
    }
}

fn stderr_line(o: &Output) -> String {
    let s = String::from_utf8_lossy(&o.stderr);
    s.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()).unwrap_or_else(|| rust_i18n::t!("fw.no_message").into_owned())
}

fn command_with_cap(program: &str, args: &[&str]) -> Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(program);
    cmd.args(args);
    // SAFETY: между fork и exec зовутся только системные вызовы
    // (capget/capset/prctl) без выделения памяти и блокировок.
    unsafe {
        cmd.pre_exec(pass_net_admin);
    }
    cmd
}

fn run_with_cap(program: &str, args: &[&str]) -> io::Result<Output> {
    command_with_cap(program, args).stdin(Stdio::null()).output()
}

fn run_with_cap_stdin(program: &str, args: &[&str], input: &str) -> io::Result<Output> {
    let mut child = command_with_cap(program, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Ошибку записи не возвращаем: если nft вышел раньше, чем дочитал
    // (отверг первую же строку), она — EPIPE, а причина — в его stderr.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    child.wait_with_output()
}

fn spawn_with_cap(program: &str, args: &[&str]) -> io::Result<Child> {
    command_with_cap(program, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// В дочернем процессе до exec: передать CAP_NET_ADMIN через ambient-набор
/// и умереть вместе с родителем.
///
/// Полномочие файла (`setcap`) на exec дочерней программы не переходит:
/// у `nft` своих файловых полномочий нет. Ambient-набор — штатный способ
/// передать его обычной программе; для этого оно должно быть и в
/// inheritable-наборе. Меняется это уже после fork, так что сам прокси и
/// его прочие дочерние процессы ничего лишнего не получают.
fn pass_net_admin() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;

    let mut header = Header { version: VERSION_3, pid: 0 };
    let mut data = [Data::default(); 2];
    // SAFETY: структуры по формату ядра для _LINUX_CAPABILITY_VERSION_3.
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut header as *mut Header, data.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        // Нет права у самого прокси — передавать нечего. Не ошибка: пусть
        // программа запустится и сама скажет, что прав нет.
        if data[0].permitted & (1 << CAP_NET_ADMIN) == 0 {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            return Ok(());
        }
        data[0].inheritable |= 1 << CAP_NET_ADMIN;
        if libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
            CAP_NET_ADMIN as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        // Родитель погиб — и мы следом: nft сам увидит закрытый stdin, но
        // так надёжнее, если stdin кто-то унаследовал.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ruleset() {
        let r = ruleset(&Plan { gid: 951, port: 1083, dns_port: 1053, quic: true, calls: true, packet: false, hello_by_payload: true });
        assert!(r.starts_with("add table inet net_surgeon { flags owner; }\n"));
        assert!(r.contains("nat_out meta skgid 951 return"));
        assert!(r.contains("tcp dport 443 redirect to :1083"));
        assert!(r.contains("udp dport 53 redirect to :1053"));
        assert!(r.contains("meta mark set 0x1"));
        assert!(r.contains("tproxy ip to 127.0.0.1:1083 accept"));
        assert!(r.contains("udp dport { 3478-3481, 19294-19344, 50000-65535 } meta mark set 0x1"));
        // Метка — только своему трафику пользователя: не сокетам ядра
        // (WireGuard) и не пакетам с чужой меткой.
        assert!(r.lines().filter(|l| l.contains("meta mark set")).all(|l| l.contains("meta mark 0 meta skgid != 951")));
        assert!(r.contains("ip6 daddr != ::1 udp dport 53 redirect to :1053"));
        assert!(r.contains("ip daddr != { 127.0.0.0/8, "), "локальные адреса по портам звонков не трогаем");
        assert!(r.contains("ip daddr { 149.154.160.0/20, "));
        // Исключение своей группы должно идти раньше перехвата в каждой цепочке.
        let skip = r.find("nat_out meta skgid").unwrap();
        assert!(skip < r.find("redirect to :1083").unwrap());
        let skip = r.find("mark_out meta skgid").unwrap();
        assert!(skip < r.find("meta mark set").unwrap());
    }

    #[test]
    fn without_dns_and_quic() {
        let r = ruleset(&Plan { gid: 951, port: 1083, dns_port: 0, quic: false, calls: true, packet: false, hello_by_payload: true });
        assert!(!r.contains("dport 53"));
        assert!(!r.contains("tproxy"));
        assert!(!r.contains("mark_out"));
        assert!(!r.contains("50000-65535"), "звонки идут дорогой QUIC и без неё не ставятся");
        assert!(r.contains("tcp dport 443 redirect to :1083"));
    }

    /// Пакетный режим: TCP/443 уходит в очередь, а не разворачивается на
    /// слушатель. DNS-редирект остаётся, свои пакеты мимо, пробы — в очередь.
    #[test]
    fn packet_mode_queues_tcp_instead_of_redirect() {
        use crate::bypass::packet_mode::{PROBE_FWMARK, REINJECT_FWMARK};
        let r = ruleset(&Plan { gid: 951, port: 1083, dns_port: 1053, quic: false, calls: false, packet: true, hello_by_payload: true });
        assert!(!r.contains("nat_out tcp dport 443 redirect"), "IPv4 на слушатель не разворачивается");
        assert!(r.contains(&format!("queue num {NFQ_QUEUE}")));
        assert!(r.contains("udp dport 53 redirect to :1053"), "DNS по-прежнему заворачивается");
        // Только ClientHello — по началу данных, а не по флагам.
        assert!(r.contains(&format!("meta nfproto ipv4 {HELLO_BY_PAYLOAD} queue num")));
        assert!(!r.contains("tcp flags"));
        // IPv6 — на слушатель.
        assert!(r.contains("nat_out meta nfproto ipv6 tcp dport 443 redirect to :1083"));
        // Старый nft — прежнее правило по флагам.
        let old = ruleset(&Plan { gid: 951, port: 1083, dns_port: 0, quic: false, calls: false, packet: true, hello_by_payload: false });
        assert!(old.contains(&format!("meta nfproto ipv4 {HELLO_BY_FLAGS} queue num")));
        // Переотправленные сегменты — мимо; пробы (по своей метке) — в очередь.
        assert!(r.contains(&format!("queue_out meta mark {REINJECT_FWMARK:#x} return")));
        assert!(r.contains(&format!("queue_out meta mark {PROBE_FWMARK:#x}")));
        // Проба ловится РАНЬШЕ исключения группы прокси, обычный трафик — позже.
        let probe = r.find(&format!("meta mark {PROBE_FWMARK:#x}")).unwrap();
        let skip = r.find("queue_out meta skgid").unwrap();
        assert!(probe < skip, "проба заворачивается несмотря на группу прокси");
    }
}
