//! Прозрачный режим Windows: перехват драйвером WinDivert.
//!
//! # Зачем
//!
//! В Linux соединения заворачивает на слушатель правило nftables, а
//! исходный адрес помнит conntrack. В Windows ни того, ни другого нет, и
//! без перехвата через обход шло только то, что берёт системный прокси:
//! браузеры, но не Discord, не игры и не программы со своим сетевым стеком.
//!
//! WinDivert — подписанный драйвер, который отдаёт пакеты в программу и
//! принимает их обратно. На нём же работают GoodbyeDPI и zapret (winws).
//!
//! Как и они, TCP обходится прямо на пакетах ([`tcp`], [`desync`]): через
//! программу идёт только начало ClientHello и первый ответ сервера, а всё
//! остальное соединение остаётся в ядре. Раньше каждое соединение на 443
//! разворачивалось на прозрачный слушатель целиком, как в примере
//! streamdump, и через программу шёл каждый пакет в обе стороны. Под
//! нагрузкой пакеты стояли в очереди драйвера (до 2 с по умолчанию), и
//! пинг рос в разы. Разворот ([`nat`]) остался только для Telegram, когда
//! задан ретранслятор: его трафик уходит в воркер, а не к серверу.
//!
//! UDP (QUIC, звонки, DNS) обрабатывается на пакетах ([`udp`]).
//!
//! # Условия
//!
//! * Права администратора: без них драйвер не загрузить. Программа без
//!   них работает как раньше, через системный прокси.
//! * `WinDivert.dll` и `WinDivert64.sys` рядом с `net_surgeon.exe`, они
//!   входят в архив для Windows.
//!
//! Перехват живёт, пока открыт дескриптор. Упади программа как угодно,
//! система его закроет, и соединения пойдут напрямую, как без неё.

#[cfg(windows)]
mod ffi;
pub mod desync;
pub mod nat;
pub mod tcp;
pub mod udp;

#[cfg(windows)]
pub use imp::*;

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Instant;

    use super::ffi::{self, Address, Handle};
    use super::nat::{Nat, Verdict, HTTPS_PORT};
    use super::tcp::{Engine, Env, Outbound};
    use crate::config::BypassParams;
    use crate::engine::strategy::StrategyStore;
    use crate::proxy::adaptive::{self, Selected};
    use super::udp::{self, Policy, Step, Tracker};
    use crate::bypass::{needs_bypass, random};
    use crate::config::Socks5JunkParams;
    use crate::observability::logging::{log_t, LogLevel, LogSender};
    use crate::observability::metrics::Metrics;
    use crate::proxy::socks5::udp::UdpPolicy;
    use crate::proxy::udp::session;

    /// Что нужно перехвату UDP: решать, какие потоки обходить, и чем.
    pub struct UdpContext {
        pub policy: UdpPolicy,
        pub junk: Socks5JunkParams,
        pub metrics: Arc<Metrics>,
        /// DoH-релей, куда отдавать перехваченные DNS-запросы. `None` — DNS
        /// не перехватывается.
        pub dns_relay: Option<SocketAddr>,
        /// Рантайм для ожидания ответов релея: поток перехвата ждать не может.
        pub runtime: tokio::runtime::Handle,
    }

    impl UdpContext {
        /// Слать ли мусор перед звонками: как в Linux, выключается
        /// `calls = false` или общим выключателем обхода.
        fn calls(&self) -> bool {
            self.policy.is_enabled && self.junk.calls
        }

        /// Что перехватывается — для строки в логе, как в Linux.
        pub fn describe(&self) -> String {
            let mut what = vec!["TCP/443".to_string(), "QUIC".to_string()];
            if self.calls() {
                what.push(rust_i18n::t!("fw.calls").into_owned());
            }
            if self.dns_relay.is_some() {
                what.push("DNS".into());
            }
            what.join(", ")
        }
    }

    /// Что нужно перехвату TCP: выбирать стратегию и засчитывать её исход.
    pub struct TcpContext {
        pub strategies: Arc<StrategyStore>,
        pub bypass_params: BypassParams,
        pub ttl_hours: u64,
    }

    /// Куда шло перехваченное соединение.
    ///
    /// Слушатель видит сервер клиентом: развёрнутый пакет приходит от его
    /// адреса и с порта приложения. Порт назначения всегда 443 — другие
    /// не перехватываются.
    pub fn original_dst(peer: SocketAddr) -> Option<SocketAddr> {
        // С петли развёрнутых пакетов не бывает: это кто-то подключился
        // к порту напрямую, и никакого «исходного адреса» у него нет.
        (!peer.ip().is_loopback()).then(|| SocketAddr::new(peer.ip(), HTTPS_PORT))
    }

    /// Работающий перехват. Останавливается при уничтожении.
    ///
    /// TCP и UDP перехватываются разными дескрипторами, каждый в своём
    /// потоке: пакеты звонка не должны ждать в одной очереди с ClientHello.
    pub struct Diverter {
        handles: Vec<Arc<Handle>>,
        threads: Vec<std::thread::JoinHandle<()>>,
        port: u16,
    }

    impl Diverter {
        /// Включает перехват на слушатель `port`. Слушатель к этому моменту
        /// уже должен быть поднят: иначе первые перехваченные соединения
        /// получили бы отказ.
        pub fn start(port: u16, tcp_ctx: TcpContext, ctx: UdpContext, log_tx: &LogSender) -> Result<Diverter, String> {
            // Что попадает в программу, см. tcp::filter и udp::filter. Петля
            // не нужна: на 127.0.0.1 никто ничего не обходит, а свои запросы
            // к DoH-релею иначе поймались бы снова.
            let telegram: Option<Vec<_>> = crate::proxy::telegram::relay()
                .map(|_| crate::proxy::telegram::networks_v4().collect());
            let tcp_filter = super::tcp::filter(port, telegram.as_deref());
            let udp_filter = format!("!loopback and {}", udp::filter(ctx.dns_relay.is_some(), ctx.calls()));
            // Оба открываются до запуска потоков: не открылся второй — первый
            // закроется вместе с Arc, и перехват не останется наполовину.
            let tcp = Arc::new(Handle::open(&tcp_filter)?);
            let udp = Arc::new(Handle::open(&udp_filter)?);
            allow_in_firewall(port, log_tx);

            // Не запустился второй поток — Drop остановит первый.
            let mut diverter = Diverter { handles: vec![Arc::clone(&tcp), Arc::clone(&udp)], threads: Vec::new(), port };
            // До запуска потоков: соединения прокси и пробы диагностики
            // должны помечаться с первого же ClientHello.
            crate::bypass::packet_mode::set_active(true);
            let env = WinEnv {
                tcp: tcp_ctx,
                policy: ctx.policy.clone(),
                log_tx: log_tx.clone(),
            };
            let runtime = ctx.runtime.clone();
            let log = log_tx.clone();
            diverter.threads.push(
                std::thread::Builder::new()
                    .name("windivert-tcp".into())
                    .spawn(move || {
                        // Выбор стратегии запускает диагностику и пишет файл
                        // стратегий — это задачи рантайма tokio.
                        let _rt = runtime.enter();
                        run_tcp(&tcp, port, &env, &log)
                    })
                    .map_err(|e| e.to_string())?,
            );
            let log = log_tx.clone();
            diverter.threads.push(
                std::thread::Builder::new()
                    .name("windivert-udp".into())
                    .spawn(move || run_udp(&udp, &ctx, &log))
                    .map_err(|e| e.to_string())?,
            );
            Ok(diverter)
        }
    }

    impl Drop for Diverter {
        fn drop(&mut self) {
            crate::bypass::packet_mode::set_active(false);
            for h in &self.handles {
                h.shutdown();
            }
            for t in self.threads.drain(..) {
                let _ = t.join();
            }
            remove_firewall_rule(self.port);
        }
    }

    /// Принимает пакеты, пока перехват не закрыт, и отдаёт их `on_packet`.
    /// Когда цикл кончился, дескриптор закрыт: после shutdown драйвер
    /// больше не забирает пакеты, и они идут мимо перехвата, как будто
    /// программы нет.
    fn recv_loop(handle: &Handle, log_tx: &LogSender, mut on_packet: impl FnMut(&mut [u8], Address)) {
        let mut buf = vec![0u8; ffi::MTU_MAX];
        let mut errors = 0u32;
        loop {
            let mut addr = Address::zeroed();
            let len = match handle.recv(&mut buf, &mut addr) {
                None => break,
                Some(Ok(len)) => {
                    errors = 0;
                    len
                }
                // Слишком большой пакет и прочие разовые сбои: пакет потерян,
                // отправитель его повторит. Перехват из-за этого не бросаем.
                Some(Err(e)) => {
                    errors += 1;
                    if errors < MAX_RECV_ERRORS {
                        continue;
                    }
                    // Сбой не разовый. Дескриптор закрывается ниже: иначе
                    // пакеты копились бы в драйвере, и без сети осталась
                    // бы вся машина.
                    log_t(log_tx, LogLevel::Error, "log.windivert_failed", vec![("error", e.to_string())]);
                    break;
                }
            };
            on_packet(&mut buf[..len], addr);
        }
        handle.shutdown();
    }

    fn run_udp(handle: &Arc<Handle>, ctx: &UdpContext, log_tx: &LogSender) {
        let mut flows: Tracker<(Vec<u8>, Address)> = Tracker::default();
        recv_loop(handle, log_tx, |pkt, addr| {
            let Some(u) = udp::parse(pkt) else {
                handle.send(pkt, &addr);
                return;
            };
            match ctx.dns_relay {
                Some(relay) if u.dport == 53 => forward_dns(handle, &ctx.runtime, relay, pkt.to_vec(), addr),
                _ => on_udp(handle, &mut flows, pkt, &addr, ctx, log_tx),
            }
        });
    }

    fn run_tcp(handle: &Arc<Handle>, port: u16, env: &WinEnv, log_tx: &LogSender) {
        let mut nat = Nat::new(port);
        let mut engine = Engine::new();
        let me = std::process::id();
        let mut warned = false;

        recv_loop(handle, log_tx, |pkt, mut addr| {
            let Some(t) = super::desync::parse(pkt) else {
                handle.send(pkt, &addr);
                return;
            };
            let outbound = addr.outbound();
            let now = Instant::now();

            // Разворот на слушатель: Telegram (фильтр пропускает его, только
            // когда задан ретранслятор), ответы слушателя и входящие на его
            // порт снаружи — их Nat выбрасывает.
            let to_listener = if outbound {
                t.sport == port
                    || (t.dport == HTTPS_PORT && crate::proxy::telegram::is_telegram(t.dst, t.dport))
            } else {
                t.dport == port
            };
            if !to_listener {
                if outbound {
                    match engine.outbound(pkt, now, env) {
                        Outbound::Send(packets) => {
                            for mut p in packets {
                                handle.fix_checksums(&mut p, &mut addr);
                                handle.send(&p, &addr);
                            }
                        }
                        Outbound::Reset(mut rst) => {
                            addr.set_outbound(false);
                            handle.fix_checksums(&mut rst, &mut addr);
                            handle.send(&rst, &addr);
                        }
                    }
                } else {
                    engine.inbound(pkt, now, env);
                    handle.send(pkt, &addr);
                }
                return;
            }

            let verdict = nat.process(pkt, outbound, now, |ip, port| {
                owner_pid(ip, port).is_some_and(|pid| pid != me)
            });
            match verdict {
                Verdict::Pass => {
                    handle.send(pkt, &addr);
                }
                Verdict::Drop => {}
                Verdict::Reflect => {
                    addr.set_outbound(false);
                    handle.fix_checksums(pkt, &mut addr);
                    handle.send(pkt, &addr);
                }
                Verdict::GaveUp => {
                    // Один раз за запуск: дальше каждое соединение будет
                    // откатываться так же, и лог утонул бы в одинаковом.
                    if !warned {
                        warned = true;
                        log_t(log_tx, LogLevel::Warning, "log.windivert_listener_silent", vec![
                            ("port", port.to_string()),
                        ]);
                    }
                    handle.send(pkt, &addr);
                }
            }
        });
    }

    /// Сколько ошибок приёма подряд терпеть, прежде чем выключить перехват.
    const MAX_RECV_ERRORS: u32 = 100;

    /// Остальная программа для перехвата TCP.
    struct WinEnv {
        tcp: TcpContext,
        policy: UdpPolicy,
        log_tx: LogSender,
    }

    impl WinEnv {
        fn adaptive(&self) -> adaptive::Context<'_> {
            adaptive::Context {
                strategies: &self.tcp.strategies,
                bypass_params: &self.tcp.bypass_params,
                ttl_hours: self.tcp.ttl_hours,
                log_tx: &self.log_tx,
            }
        }
    }

    impl Env for WinEnv {
        fn take_mark(&self, local_port: u16) -> Option<crate::bypass::packet_mode::Mark> {
            crate::bypass::packet_mode::take(local_port)
        }
        fn is_blocked(&self, domain: &str) -> bool {
            crate::block::is_blocked(domain)
        }
        fn needs_bypass(&self, domain: &str) -> bool {
            needs_bypass(self.policy.is_enabled, domain, &self.policy.bypass_domains)
        }
        fn select(&self, domain: &str, hello_len: usize) -> Selected {
            adaptive::select_packet(&self.adaptive(), domain, hello_len)
        }
        fn record(&self, domain: &str, selected: Selected, responded: bool) {
            adaptive::record_outcome(&self.adaptive(), domain, selected, responded);
        }
        fn remember(&self, ip: IpAddr, domain: &str) {
            self.policy.ip_cache.insert(ip, domain.to_string());
        }
        fn lookup(&self, ip: IpAddr) -> Option<String> {
            self.policy.ip_cache.lookup(&ip)
        }
        fn decoy(&self, len: usize) -> Vec<u8> {
            crate::bypass::tls::build_client_hello_sized(&self.tcp.bypass_params.fake_sni, len)
        }
        fn log_intercepted(&self, domain: &str, dst: IpAddr, bypass: bool) {
            log_t(&self.log_tx, LogLevel::Success, "log.transparent_tunnel", vec![
                ("domain", domain.to_string()),
                ("addr", SocketAddr::new(dst, HTTPS_PORT).to_string()),
                ("bypass", bypass.to_string()),
            ]);
        }
        fn log_applied(&self, domain: &str, detail: &str) {
            log_t(&self.log_tx, LogLevel::Warning, "log.transparent_applied", vec![
                ("domain", domain.to_string()),
                ("detail", detail.to_string()),
            ]);
        }
        fn log_blocked(&self, domain: &str) {
            log_t(&self.log_tx, LogLevel::Info, "log.blocked", vec![
                ("domain", domain.to_string()),
                ("via", "SNI".to_string()),
            ]);
        }
    }

    fn on_udp(
        handle: &Arc<Handle>,
        flows: &mut Tracker<(Vec<u8>, Address)>,
        pkt: &[u8],
        addr: &Address,
        ctx: &UdpContext,
        log_tx: &LogSender,
    ) {
        // То же решение, что в прозрачном UDP-режиме Linux (transparent_udp).
        let mut domain = None;
        let mut call = false;
        let (step, count) = flows.process(
            pkt,
            Instant::now(),
            |u, payload| {
                domain = ctx.policy.ip_cache.lookup(&u.dst);
                if domain.as_deref().is_some_and(crate::block::is_blocked) {
                    return Policy::Block;
                }
                let bypass = domain
                    .as_deref()
                    .is_some_and(|d| needs_bypass(ctx.policy.is_enabled, d, &ctx.policy.bypass_domains));
                call = !bypass && ctx.calls() && session::is_call_flow(payload, u.dst);
                if bypass || call {
                    Policy::Junk { quic: session::is_quic_initial(payload) }
                } else {
                    Policy::Pass
                }
            },
            || (pkt.to_vec(), *addr),
        );
        for _ in 0..count.opened {
            ctx.metrics.quic_session_opened();
        }
        for _ in 0..count.closed {
            ctx.metrics.quic_session_closed();
        }

        match step {
            Step::Pass => {
                handle.send(pkt, addr);
            }
            Step::Queued => {}
            Step::Drop { first } => {
                if first && let Some(d) = domain {
                    log_t(log_tx, LogLevel::Info, "log.blocked", vec![
                        ("domain", d),
                        ("via", "QUIC".to_string()),
                    ]);
                }
            }
            Step::Junk { rx, quic } => {
                if let Some(u) = udp::parse(pkt) {
                    let target = SocketAddr::new(u.dst, u.dport).to_string();
                    if call {
                        log_t(log_tx, LogLevel::Info, "log.call_junk", vec![("addr", target)]);
                    } else {
                        log_t(log_tx, LogLevel::Info, "log.tproxy_session", vec![
                            ("addr", target),
                            ("domain", domain.unwrap_or_else(|| u.dst.to_string())),
                            ("bypass", "true".to_string()),
                        ]);
                    }
                }
                spawn_junk_sender(Arc::clone(handle), rx, quic, ctx.junk.clone(), Arc::clone(&ctx.metrics));
            }
        }
    }

    /// Шлёт мусор, потом всё из очереди потока по порядку. Отдельным
    /// потоком: паузы между мусором остановили бы перехват всей машины.
    /// Завершается, когда перехват закрывает очередь.
    fn spawn_junk_sender(
        handle: Arc<Handle>,
        rx: std::sync::mpsc::Receiver<(Vec<u8>, Address)>,
        quic: bool,
        junk: Socks5JunkParams,
        metrics: Arc<Metrics>,
    ) {
        let _ = std::thread::Builder::new().name("udp-junk".into()).spawn(move || {
            let Ok((first, addr)) = rx.recv() else { return };
            if let Some(u) = udp::parse(&first) {
                for i in 0..junk.count {
                    let mut fake = udp::with_payload(&first, &u, &session::junk_packet(&junk, quic));
                    let mut fake_addr = addr;
                    handle.fix_checksums(&mut fake, &mut fake_addr);
                    handle.send(&fake, &fake_addr);
                    if quic {
                        metrics.quic_initial_sent();
                    }
                    // Пауза только между мусором, как в Linux: хвостовая
                    // задерживала бы настоящий пакет ни за чем.
                    if i + 1 < junk.count {
                        let delay = random::in_range(junk.delay_min_ms, junk.delay_max_ms);
                        std::thread::sleep(std::time::Duration::from_millis(delay));
                    }
                }
            }
            handle.send(&first, &addr);
            for (pkt, addr) in rx {
                handle.send(&pkt, &addr);
            }
        });
    }

    /// Сколько ждать ответа DoH-релея. Системный резолвер Windows сам
    /// повторяет запрос через секунду-две, так что дольше ждать незачем.
    const DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Отдаёт DNS-запрос DoH-релею и возвращает ответ приложению от имени
    /// сервера, которого оно спрашивало. Как правило `udp dport 53 redirect`
    /// в Linux: запросы уходят шифрованными, и заодно наполняется кэш
    /// «адрес → домен», по которому решается обход QUIC и звонков.
    ///
    /// Сам запрос не отпускается: ответ провайдерского DNS мог бы прийти
    /// раньше и подменить настоящий.
    fn forward_dns(
        handle: &Arc<Handle>,
        runtime: &tokio::runtime::Handle,
        relay: SocketAddr,
        query: Vec<u8>,
        addr: Address,
    ) {
        let handle = Arc::clone(handle);
        runtime.spawn(async move {
            let Some(u) = udp::parse(&query) else { return };
            let Ok(sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
            if sock.send_to(&query[u.ip_len + 8..], relay).await.is_err() {
                return;
            }
            let mut buf = vec![0u8; 65535];
            let Ok(Ok(n)) = tokio::time::timeout(DNS_TIMEOUT, sock.recv(&mut buf)).await else { return };
            let mut answer = udp::reply(&query, &u, &buf[..n]);
            let mut addr = addr;
            addr.set_outbound(false);
            handle.fix_checksums(&mut answer, &mut addr);
            handle.send(&answer, &addr);
        });
    }

    /// Какой процесс владеет TCP-сокетом с этим локальным адресом и портом.
    ///
    /// Спрашивается на SYN: к этому моменту сокет уже привязан и виден
    /// в таблице системы в состоянии SYN_SENT.
    fn owner_pid(local: IpAddr, port: u16) -> Option<u32> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        };
        const AF_INET: u32 = 2;
        const AF_INET6: u32 = 23;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

        let af = if local.is_ipv4() { AF_INET } else { AF_INET6 };
        // u32, а не u8: строки таблицы выровнены по 4 байта.
        let mut table: Vec<u32> = Vec::new();
        let mut size = 0u32;
        // Таблица может вырасти между запросом размера и чтением.
        for _ in 0..4 {
            let rc = unsafe {
                GetExtendedTcpTable(table.as_mut_ptr().cast(), &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
            };
            match rc {
                0 => break,
                ERROR_INSUFFICIENT_BUFFER => table = vec![0; (size as usize).div_ceil(4) + 16],
                _ => return None,
            }
        }
        let count = *table.first()? as usize;
        let rows = table.as_ptr().wrapping_add(1);
        // Порты в таблице в сетевом порядке, в младших двух байтах.
        let port_of = |raw: u32| u16::from_be(raw as u16);

        match local {
            IpAddr::V4(ip) => {
                let rows = unsafe { std::slice::from_raw_parts(rows.cast::<MIB_TCPROW_OWNER_PID>(), count) };
                rows.iter()
                    .find(|r| {
                        let addr = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
                        port_of(r.dwLocalPort) == port && (addr == ip || addr.is_unspecified())
                    })
                    .map(|r| r.dwOwningPid)
            }
            IpAddr::V6(ip) => {
                let rows = unsafe { std::slice::from_raw_parts(rows.cast::<MIB_TCP6ROW_OWNER_PID>(), count) };
                rows.iter()
                    .find(|r| {
                        let addr = Ipv6Addr::from(r.ucLocalAddr);
                        port_of(r.dwLocalPort) == port && (addr == ip || addr.is_unspecified())
                    })
                    .map(|r| r.dwOwningPid)
            }
        }
    }

    fn rule_name(port: u16) -> String {
        format!("net_surgeon transparent {port}")
    }

    /// Разрешает входящие на порт слушателя в брандмауэре Windows.
    ///
    /// Развёрнутый пакет система принимает как входящий из сети, и
    /// брандмауэр проверяет его как любой другой. В профиле «Общедоступная
    /// сеть» он такие по умолчанию режет, и перехваченные соединения
    /// повисали бы. Правило только для этой программы и этого порта; из
    /// сети до порта всё равно не достучаться, такие пакеты выбрасываются.
    fn allow_in_firewall(port: u16, log_tx: &LogSender) {
        let Ok(exe) = std::env::current_exe() else { return };
        remove_firewall_rule(port);
        let ok = netsh(&[
            "add",
            "rule",
            &format!("name={}", rule_name(port)),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
            &format!("program={}", exe.display()),
        ]);
        if !ok {
            log_t(log_tx, LogLevel::Warning, "log.windivert_firewall_failed", vec![("port", port.to_string())]);
        }
    }

    fn remove_firewall_rule(port: u16) {
        netsh(&["delete", "rule", &format!("name={}", rule_name(port))]);
    }

    fn netsh(args: &[&str]) -> bool {
        std::process::Command::new("netsh")
            .args(["advfirewall", "firewall"])
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}
