# net_surgeon

[Русский](README.md) | **English**

Bypasses ISP website blocking by deep packet inspection (DPI) on **Windows**,
**Linux** and **Android**. It picks a working bypass technique for each site
by itself: it tries several techniques and chooses by statistics, not by a
single lucky attempt.

Built for Russian ISPs (YouTube, Discord, AI services closed to Russia,
Telegram), but the techniques work against SNI-based DPI in general.

## Download

| System | File | How to run |
|---|---|---|
| **Windows** 10/11 | `net_surgeon-…-x86_64-windows.zip` | unpack, run `net_surgeon.exe` |
| **Linux** x86_64 | `net_surgeon-…-x86_64-linux.tar.gz` | unpack, run `./run.sh` |
| **Android** 8+ (arm64) | `net_surgeon-…-arm64.apk` | install, tap “Turn on” |

All files are on the [latest release](https://github.com/rozinanime-sketch/net_surgeon/releases/latest) page.

## Features

- **Bypasses DPI** that filters by site name: splits the TLS ClientHello into
  several records, cuts the packet in the middle of the name, reorders the
  pieces (disorder), inserts an out-of-band byte.
- **Picks the technique itself** for each site, remembers it and re-measures
  it when it stops working.
- **No setup needed:** on Windows it sets the system proxy by itself, on
  Linux it intercepts the whole machine's traffic, on Android it works as a
  VPN without root.
- **Encrypts DNS** (DoH) so the ISP can't spoof site addresses.
- **Opens AI services closed to Russia** (ChatGPT, Claude, Gemini, Grok,
  Copilot) through a smart DNS.
- **Telegram** goes through your own free Cloudflare worker when the ISP
  blocks its addresses entirely ([guide, in Russian](cloudflare/README.md)).

**What it can't do:** change your IP address. If a service itself refuses
your country, only a VPN helps (except the AI services above).

The interface is in English and Russian and follows the system language.

## Quick start

### Windows

1. Download the Windows archive and unpack it anywhere.
2. Double-click `net_surgeon.exe`. No administrator rights needed.
3. If you see “Windows protected your PC”, click “More info → Run anyway”:
   the program has no paid code signature.

While the window is open, the browser goes through the bypass. Close the
window and the proxy settings go back to what they were.

> There is no transparent mode on Windows yet: the bypass covers browsers and
> programs that use the Windows proxy settings. To set the proxy yourself,
> put `system_proxy = false` in `config.toml`.

### Linux

```sh
curl -LO https://github.com/rozinanime-sketch/net_surgeon/releases/download/v0.6.2/net_surgeon-0.6.2-x86_64-linux.tar.gz
tar xzf net_surgeon-0.6.2-x86_64-linux.tar.gz
cd net_surgeon-0.6.2
./run.sh
```

The build is static and runs on any distribution. On the first run the
script asks for your `sudo` password once, to grant the program the right to
intercept traffic. Press `q` to quit: interception is removed automatically.

Requires `nft` (nftables), `iproute2` and `setcap` (package `libcap` on Arch,
`libcap2-bin` on Debian and Ubuntu).

### Android

Install the APK, tap “Turn on” and accept the VPN connection. It is not a
real VPN: traffic doesn't leave the phone. Details (in Russian) are in
[android/README.md](android/README.md).

### Your own sites

The bypass applies only to sites listed in `bypass_domains.txt`, one per
line. Subdomains count: `youtube.com` also covers `m.youtube.com`. You can
also add a site from the program itself, in the “Domains” menu.

## Troubleshooting

| Problem | What to do |
|---|---|
| **Windows:** no internet after quitting | Settings → Network & Internet → Proxy → turn the proxy off. The program was probably killed from Task Manager |
| **Linux:** no internet after quitting | `./run.sh off` |
| A site doesn't open | Check that it is in `bypass_domains.txt`. If it is, run “Diagnostics” for it or delete `strategies.txt` to re-measure everything |
| Nothing is bypassed | Turn off your VPN: through it the ISP doesn't see the traffic, so the bypass is useless |
| The site says it's unavailable in your country | That's the site blocking you, not the ISP. Only a VPN helps |

The program has been tested on one network. If it doesn't work for you,
[describe the problem](https://github.com/rozinanime-sketch/net_surgeon/issues)
and attach the log from the program window.

<details>
<summary><b>Linux: other modes and manual proxy</b></summary>

```sh
./run.sh plain        # proxy ports only, no interception
./run.sh --diagnose   # diagnostics only, traffic is not changed
./run.sh off          # emergency: remove interception and restore the network
./run.sh status       # show whether interception rules are active
```

In `plain` mode, point your application at the proxy yourself:

| What | Address |
|---|---|
| HTTP/HTTPS | `127.0.0.1:1080` |
| SOCKS5 | `127.0.0.1:1081` |

</details>

<details>
<summary><b>Linux: how interception works and why the network shouldn't break</b></summary>

HTTPS (TCP/443), QUIC (UDP/443) and DNS (UDP/53) are intercepted. The rules
live in an nftables table owned by the program's process: the kernel deletes
it as soon as the process exits, even after `kill -9` or a crash. That's why
sudo is needed only once after download or build — to grant the program
`cap_net_admin` and the `nsproxy` group.

If the system has no `nft` or `getcap` (or `NET_SURGEON_LEGACY=1` is set),
the script takes the old `iptables` path: it asks for sudo on every run,
removes the rules on exit and keeps a watchdog for `kill -9` or a closed
window. If the network is gone after quitting on this path:

1. `./run.sh status` — check for rules;
2. `./run.sh off` — remove them. Only its own rules are removed; Docker and
   VPN rules are left alone;
3. if sudo won't let you in, reboot: the rules live only in memory.

Don't use `iptables -F`: it also wipes Docker, VPN and firewall rules.

The script's messages on this path are in Russian:

| Message | Meaning | What to do |
|---|---|---|
| `TPROXY недоступен` | The kernel has no `xt_TPROXY` module | Nothing: QUIC bypasses the tool, the browser falls back to TCP |
| `Не удалось выдать полномочия` | `setcap` failed | Install `libcap` / `libcap2-bin` |
| `IPv6 не перехватывается` | No `ip6tables` or IPv6 nat | Nothing: IPv4 only |
| `не задан doh_bootstrap_ip` | The DNS relay can't learn the DoH server address | Put the IP of the `doh_provider` server into `config.toml` |
| `Не удалось запустить сторожа` | No `setsid` | Interception is removed on a normal exit; after a crash, run `./run.sh off` |

</details>

<details>
<summary><b>Building from source</b></summary>

Requires Rust 1.88 or newer (easiest via [rustup](https://rustup.rs)).

```sh
git clone --branch v0.6.2 https://github.com/rozinanime-sketch/net_surgeon.git
cd net_surgeon
./run.sh
```

`run.sh` builds the program on first run and rebuilds it when the code
changes. Without `--branch` you get the current `main`, not a release.
Building the Android app is described (in Russian) in
[android/README.md](android/README.md).

</details>

<details>
<summary><b>Files</b></summary>

- `bypass_domains.txt` — sites the bypass applies to.
- `smart_dns_domains.txt` — sites resolved through the smart DNS.
- `config.toml` — settings. Every option has a comment (in Russian); better
  leave them alone unless needed.
- `strategies.txt` — the chosen techniques. Created automatically; delete it
  to re-measure everything from scratch.

</details>

## License

[MIT](LICENSE).
