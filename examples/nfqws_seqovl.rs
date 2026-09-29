//! Пробный пакетный обход на Linux через NFQUEUE — как nfqws в zapret.
//!
//! Тонкая обёртка над [`net_surgeon::nfqueue`]: весь движок (перехват
//! ClientHello, seqovl с приманкой Google, переотправка через raw-сокет) живёт
//! в библиотеке и общий с будущим продуктовым путём. Здесь только запуск.
//!
//! Нужен, чтобы проверить seqovl на живом трафике: снимает ли он заморозку
//! после ~16 КБ. IPv4, локально сгенерированный трафик.
//!
//! # Запуск
//!
//! Проще всего через `./run.sh seqovl` — он соберёт тестер, поднимет правило
//! очереди и снимет его при выходе. Вручную то же самое:
//!
//! ```text
//! cargo build --example nfqws_seqovl --release
//! sudo nft add table inet ns_test
//! sudo nft add chain inet ns_test out '{ type filter hook output priority 0; }'
//! sudo nft add rule inet ns_test out meta mark != 0x73 tcp dport 443 tcp flags '&' '(fin|syn|rst|psh|ack)' == '(psh|ack)' queue num 0
//! sudo ./target/release/examples/nfqws_seqovl 0
//! sudo nft delete table inet ns_test
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nfqws_seqovl работает только на Linux (NFQUEUE).");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    let queue_num: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    net_surgeon::nfqueue::run_seqovl_stand(queue_num)
}
