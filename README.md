# RustyBird

A sing-box client for GNOME. Rust, GTK4, libadwaita.

## English

RustyBird drives the sing-box binary and exposes what it can actually do: VLESS, VMess,
Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC, AnyTLS, ShadowTLS, Snell, SSH, Tor, HTTP,
SOCKS, and WireGuard endpoints. TUN mode, system proxy, rule based routing, DNS over
HTTPS/TLS/QUIC/HTTP3, FakeIP, subscriptions and Clash config import.

Every per-node option is editable, including transports, multiplexing, UDP over TCP,
REALITY, uTLS and ECH. If you would rather not use the UI for any of that, hand it a
complete sing-box JSON profile and the core takes over the routing.

**Build**

You need Rust, the GTK4 and libadwaita development files, and a sing-box binary.

```
cargo build --release
./target/release/rustybird
```

If sing-box is not in `/usr/bin`, set the path in Settings.

**Tests**

```
cargo test
```

Point `RUSTYBIRD_SINGBOX_BIN` at a sing-box binary to also check every generated config
against the real core.

## فارسی

کلاینت sing-box برای گنوم. با Rust و GTK4 نوشته شده.

باینری sing-box را اجرا می‌کند و هر چیزی که خودش پشتیبانی می‌کند در دسترس است:
VLESS، VMess، Trojan، Shadowsocks، Hysteria، Hysteria2، TUIC، AnyTLS، ShadowTLS،
Snell، SSH، Tor، HTTP، SOCKS و WireGuard. حالت TUN، پراکسی سیستم، مسیریابی قانون‌محور،
DNS روی HTTPS و TLS و QUIC و HTTP3، فیک‌آی‌پی، ساب‌اسکریپشن و ایمپورت کانفیگ Clash.

تنظیمات هر نود جداگانه قابل ویرایش است؛ ترنسپورت، مالتی‌پلکس، UDP over TCP، REALITY،
uTLS و ECH. اگر ترجیح می‌دهی با رابط گرافیکی سروکار نداشته باشی، یک کانفیگ کامل JSON
سینگ‌باکس بده و بقیه‌اش با خود هسته.

**ساخت**

به Rust، فایل‌های توسعهٔ GTK4 و libadwaita و یک باینری sing-box نیاز داری.

```
cargo build --release
./target/release/rustybird
```

اگر sing-box در `/usr/bin` نیست، مسیرش را از بخش تنظیمات بده.

**تست**

```
cargo test
```

اگر `RUSTYBIRD_SINGBOX_BIN` را به یک باینری sing-box اشاره بدهی، کانفیگ‌های تولیدشده با
خود هسته هم اعتبارسنجی می‌شوند.

---

GPL-3.0-or-later
