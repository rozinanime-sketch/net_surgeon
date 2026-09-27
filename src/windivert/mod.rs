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
//! TCP он не обходит сам, а только разворачивает соединения на 443 в тот
//! же прозрачный слушатель, что и в Linux ([`nat`]). Выбор стратегии, SNI,
//! запасные адреса — всё общее. QUIC обрабатывается прямо на пакетах
//! ([`quic`]): прокси для него не нужен.
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
pub mod nat;
pub mod quic;

#[cfg(windows)]
pub use imp::*;

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Instant;

    use super::ffi::{self, Address, Handle};
    use super::nat::{Nat, Verdict, HTTPS_PORT};
    use super::quic::{self, Policy, Step, Tracker};
    use crate::bypass::{fragment, needs_bypass, random};
    use crate::config::Socks5JunkParams;
    use crate::observability::logging::{log_t, LogLevel, LogSender};
    use crate::observability::metrics::Metrics;
    use crate::proxy::socks5::udp::UdpPolicy;

    /// Что нужно перехвату QUIC: решать, какие потоки обходить, и чем.
    pub struct QuicContext {
        pub policy: UdpPolicy,
        pub junk: Socks5JunkParams,
        pub metrics: Arc<Metrics>,
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
    pub struct Diverter {
        handle: Arc<Handle>,
        thread: Option<std::thread::JoinHandle<()>>,
        port: u16,
    }

    impl Diverter {
        /// Включает перехват на слушатель `port`. Слушатель к этому моменту
        /// уже должен быть поднят: иначе первые перехваченные соединения
        /// получили бы отказ.
        pub fn start(port: u16, quic: QuicContext, log_tx: &LogSender) -> Result<Diverter, String> {
            // Своё: исходящие на 443 (TCP и QUIC) и ответы слушателя. Чужое:
            // входящие на порт слушателя из сети, их выбрасываем. Петля не
            // нужна: на 127.0.0.1 никто ничего не обходит.
            let filter = format!(
                "!loopback and ((tcp and ((outbound and (tcp.DstPort == {HTTPS_PORT} or tcp.SrcPort == {port})) \
                 or (inbound and tcp.DstPort == {port}))) or (outbound and udp.DstPort == {HTTPS_PORT}))"
            );
            let handle = Arc::new(Handle::open(&filter)?);
            allow_in_firewall(port, log_tx);

            let thread = {
                let handle = Arc::clone(&handle);
                let log_tx = log_tx.clone();
                std::thread::Builder::new()
                    .name("windivert".into())
                    .spawn(move || run(&handle, port, &quic, &log_tx))
                    .map_err(|e| e.to_string())?
            };
            Ok(Diverter { handle, thread: Some(thread), port })
        }
    }

    impl Drop for Diverter {
        fn drop(&mut self) {
            self.handle.shutdown();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            remove_firewall_rule(self.port);
        }
    }

    fn run(handle: &Arc<Handle>, port: u16, ctx: &QuicContext, log_tx: &LogSender) {
        let mut nat = Nat::new(port);
        let mut quic_flows: Tracker<(Vec<u8>, Address)> = Tracker::default();
        let mut buf = vec![0u8; ffi::MTU_MAX];
        let me = std::process::id();
        let mut warned = false;
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
                // TCP его повторит. Перехват из-за этого не бросаем.
                Some(Err(e)) => {
                    errors += 1;
                    if errors < MAX_RECV_ERRORS {
                        continue;
                    }
                    // Сбой не разовый. Дескриптор закрывается ниже: иначе
                    // пакеты копились бы в драйвере, и без HTTPS осталась
                    // бы вся машина.
                    log_t(log_tx, LogLevel::Error, "log.windivert_failed", vec![("error", e.to_string())]);
                    break;
                }
            };
            let pkt = &mut buf[..len];

            if quic::parse(pkt).is_some() {
                on_udp(handle, &mut quic_flows, pkt, &addr, ctx, log_tx);
                continue;
            }

            let verdict = nat.process(pkt, addr.outbound(), Instant::now(), |ip, port| {
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
        }
        // После shutdown драйвер больше не забирает пакеты, и они идут
        // мимо перехвата, как будто программы нет.
        handle.shutdown();
    }

    /// Сколько ошибок приёма подряд терпеть, прежде чем выключить перехват.
    const MAX_RECV_ERRORS: u32 = 100;

    fn on_udp(
        handle: &Arc<Handle>,
        flows: &mut Tracker<(Vec<u8>, Address)>,
        pkt: &[u8],
        addr: &Address,
        ctx: &QuicContext,
        log_tx: &LogSender,
    ) {
        let mut domain = None;
        let (step, count) = flows.process(
            pkt,
            Instant::now(),
            |dst| {
                let Some(d) = ctx.policy.ip_cache.lookup(&dst) else { return Policy::Pass };
                let policy = if crate::block::is_blocked(&d) {
                    Policy::Block
                } else if needs_bypass(ctx.policy.is_enabled, &d, &ctx.policy.bypass_domains) {
                    Policy::Bypass
                } else {
                    Policy::Pass
                };
                domain = Some(d);
                policy
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
            Step::Junk(rx) => {
                if let Some(u) = quic::parse(pkt) {
                    log_t(log_tx, LogLevel::Info, "log.tproxy_session", vec![
                        ("addr", SocketAddr::new(u.dst, u.dport).to_string()),
                        ("domain", domain.unwrap_or_else(|| u.dst.to_string())),
                        ("bypass", "true".to_string()),
                    ]);
                }
                spawn_junk_sender(Arc::clone(handle), rx, ctx.junk.clone(), Arc::clone(&ctx.metrics));
            }
        }
    }

    /// Шлёт поддельные Initial, потом всё из очереди потока по порядку.
    /// Отдельным потоком: паузы между мусором остановили бы перехват всей
    /// машины. Завершается, когда перехват закрывает очередь.
    fn spawn_junk_sender(
        handle: Arc<Handle>,
        rx: std::sync::mpsc::Receiver<(Vec<u8>, Address)>,
        junk: Socks5JunkParams,
        metrics: Arc<Metrics>,
    ) {
        let _ = std::thread::Builder::new().name("quic-junk".into()).spawn(move || {
            let Ok((first, addr)) = rx.recv() else { return };
            if let Some(u) = quic::parse(&first) {
                for i in 0..junk.count {
                    let mut fake = quic::with_payload(&first, &u, &fragment::build_fake_quic_initial());
                    let mut fake_addr = addr;
                    handle.fix_checksums(&mut fake, &mut fake_addr);
                    handle.send(&fake, &fake_addr);
                    metrics.quic_initial_sent();
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
