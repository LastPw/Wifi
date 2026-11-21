# WiFi Hunter v2.1

ابزار کامل (تک‌فایل، فقط کتابخانه استاندارد پایتون) برای **اسکن، شنود، گرفتن هندشیک، کرک آفلاین، WPS، دی‌ات و Evil Twin**.

> فقط روی شبکه‌هایی استفاده کن که مالکش هستی یا اجازه تست داری.

---

## نصب خودکار (انگلیسی، یک دستور)

```bash
bash setup.sh
```

خودش محیط را تشخیص می‌دهد (Termux / Debian-Ubuntu-Kali / Fedora / Arch / macOS / Git-Bash) و:

1. پایتون و pip را نصب/به‌روز می‌کند
2. `scapy` را نصب می‌کند (کپچر زنده)
3. ابزارهای همراه را اگر در مخزن سیستم بود نصب می‌کند: `termux-api`، `hashcat`، `aircrack-ng`، `hcxdumptool`، `reaver`، `pixiewps`، `hostapd`، `dnsmasq`، `tshark`، `iw`، `tcpdump`، `tsu`
4. روی Termux: حافظه مشترک، `wake-lock`، باز کردن تنظیمات Termux:API برای مجوز Location، تنظیم مسیر خروجی روی `~/storage/shared/WiFiHunter`
5. لانچر `wh` می‌سازد و `~/.bashrc` را وصل می‌کند
6. لیست‌های محلی را می‌سازد و لیست‌های WPA را دانلود می‌کند
7. `selftest` + `doctor` + یک اسکن واقعی می‌گیرد

سوییچ‌ها:

```bash
bash setup.sh -y --huge                 # بدون سوال + لیست‌های بزرگ (rockyou)
bash setup.sh --dry-run                 # فقط نشان بده، کاری نکن
bash setup.sh --out /sdcard/WiFiHunter  # مسیر خروجی دلخواه
bash setup.sh --skip-wordlists --no-scan-test
bash setup.sh --uninstall               # فقط لانچر/env را پاک کن
```

بعد از نصب، از هر جا: `wh`

---

## اجرا: فقط منو

```bash
python wifi_hunter.py
```

همین. هیچ سوییچی لازم نیست؛ منو همه کارها را با شماره و پرسش‌های کوتاه راه می‌برد:

```
   1) اسکن شبکه‌های اطراف            9) ارسال deauth
   2) شنود / تحلیل pcap             10) Evil Twin + portal
   3) گرفتن هندشیک و PMKID           11) گزارش HTML
   4) تبدیل pcap به هش               12) مدیریت وردلیست‌ها
   5) کرک هش (وردلیست / mask)        13) بررسی قابلیت‌ها
   6) تست یک پسورد                   14) تست صحت ابزار
   7) پسورد پیش‌فرض روتر             15) زنجیره کامل خودکار
   8) حمله WPS                        0) خروج
```

منو خودش لیست شبکه‌ها را می‌آورد، کانال و BSSID را از انتخاب تو پر می‌کند، قبل از شروع حجم فضای جستجو را نشان می‌دهد و بعد از پیدا شدن رمز، همان را در کرک بعدی استفاده می‌کند.

اگر ترجیح می‌دهی CLI بزنی، همه دستورها هنوز کار می‌کنند (`python wifi_hunter.py <command> -h`).

---

## وردلیست‌ها

از منو → `12` یا با CLI:

```bash
python wifi_hunter.py wordlists                # لیست آماده‌ها
python wifi_hunter.py wordlists fetch wifi     # ۳ لیست تخصصی WPA
python wifi_hunter.py wordlists fetch common   # ۱۰k و ۱۰۰k پرتکرار
python wifi_hunter.py wordlists fetch huge     # ۳۰۴k + rockyou (۱۳۳ مگ)
python wifi_hunter.py wordlists build          # بازسازی لیست‌های محلی
python wifi_hunter.py wordlists stats
```

لیست‌های محلی (بدون اینترنت، همین‌جا ساخته می‌شوند): `top-wifi`، `common`، `numeric` (تاریخ/موبایل ایران)، `persian` (فینگلیش)، `router-defaults`.
لیست‌های دانلودی در `wordlists/downloaded/` می‌نشینند و مستقیم به hashcat هم می‌خورند.

در کرک می‌توانی چند لیست را با هم بدهی:

```bash
python wifi_hunter.py crack -i h.22000 -w 'top-wifi,persian' --rules medium
python wifi_hunter.py crack -i h.22000 -w all --rules best
```

کلیدواژه‌ها: `curated` (همه محلی‌ها)، `downloaded`، `all`، `builtin`، یا نام/مسیر هر فایل و هر پوشه (پوشه = همه `.txt` ها).
کرک استریم است، پس rockyou کامل هم حافظه را پر نمی‌کند (۱۴ میلیون خط).

---

## نصب

هیچ dependency اجباری ندارد:

```bash
python wifi_hunter.py selftest     # صحت موتور رمزنگاری/پارس
python wifi_hunter.py doctor       # روی این سیستم چه چیزی کار می‌کند
```

اختیاری (برای امکانات زنده):

| پکیج/ابزار | کاربرد |
|---|---|
| `pip install scapy` | کپچر زنده + ارسال فریم (نیاز به Npcap روی ویندوز) |
| `pip install pywifi` | اسکن/وصل شدن بدون netsh |
| Npcap با تیک **Support raw 802.11 traffic** | مانیتور مود و اینجکشن روی ویندوز |
| `hashcat` | کرک با GPU (فرمت 22000 آماده تحویل) |
| `aircrack-ng`, `hcxdumptool`, `reaver`, `hostapd` | مسیرهای لینوکسی |

---

## دستورها (همان کارهای منو، برای اسکریپت‌نویسی)

| دستور | کار |
|---|---|
| `scan` | لیست AP با سیگنال/کانال/امنیت/WPS + پیشنهاد روش حمله |
| `sniff` | شنود زنده یا تحلیل pcap |
| `capture` | گرفتن هندشیک ۴ مرحله‌ای و PMKID |
| `hash` | pcap → `.22000` + `.json` |
| `crack` | دیکشنری/rules/mask/brute-force مالتی‌کور با potfile و resume |
| `verify` | تست یک پسورد |
| `wps` | PIN پیش‌فرض/مشتق از MAC، reaver/bully، pixie-dust |
| `deauth` | فریم deauth (scapy / Npcap / raw socket) |
| `evil` | Evil Twin + portal با **تایید خودکار پسورد** |
| `keygen` | پسورد پیش‌فرض روتر از MAC/SSID + تست روی هش |
| `wordlists` | مدیریت/دانلود/ساخت وردلیست |
| `report` / `doctor` / `selftest` / `all` | گزارش / قابلیت / تست / زنجیره کامل |

```bash
python wifi_hunter.py scan --json out/scan.json --min-signal 40
python wifi_hunter.py capture -b AA:BB:CC:DD:EE:FF --channel 6 --deauth -t 60
python wifi_hunter.py crack -i out/hashes.22000 -w wpa-top4800,common --rules best -j 8
python wifi_hunter.py crack -i out/hashes.22000 --mask '?u?l?l?l?l?l?l?l?d?d?d?d'
python wifi_hunter.py evil --ssid Home --hashes out/hashes.22000 --serve --deauth
python wifi_hunter.py report --scan out/scan.json --found out/found.json
```

`crack --list-rules` همه rule ها و preset ها (`basic`, `medium`, `best`) را چاپ می‌کند.

---

## نقشه راه حمله

1. **PMKID** (سریع‌ترین، بدون کلاینت) — `capture` خودش استخراجش می‌کند؛ چند ثانیه.
2. **هندشیک WPA2** — با `--deauth` کلاینت را مجبور به اتصال مجدد کن.
3. **WPS** — اول pixie-dust، بعد PIN؛ PIN از MAC/SSID هم ساخته می‌شود.
4. **پسورد پیش‌فرض ISP** — `keygen` الگوهای MAC-based (UPC/WLAN/dec/hex) و پیش‌فرض وندور را روی هش تست می‌کند.
5. **WPA3-SAE** — نیاز به hcxdumptool (transition/downgrade).
6. **WEP** — aircrack-ng با ARP replay.
7. **Evil Twin** — پسورد تایپ‌شده همان لحظه با هش چک و `VALID` می‌شود.

---

## اندروید با Termux

```bash
bash scripts/termux-setup.sh          # نصب قدیمی‌تر/سبک‌تر (فقط Termux)
python wifi_hunter.py                # منو
```

یا ساده‌تر: همان `bash setup.sh` در ریشه پروژه (بالاتر توضیح داده شد).

برای اسکن لازم است: اپ **Termux:API** نصب باشد، مجوز **Location** به آن داده شده باشد و GPS روشن باشد (`pkg install termux-api` هم لازم است).

منو در صفحه باریک گوشی خودش فشرده می‌شود و بک‌اند `termux-api` را انتخاب می‌کند.

**در گوشی چه کاری واقعاً انجام می‌شود:**

| کار | وضعیت |
|---|---|
| اسکن، لیست شبکه، گزارش | ✅ با Location permission |
| تحلیل pcap، `hash`، `crack`، `keygen`، `verify`، گزارش | ✅ کامل |
| کپچر زنده، دی‌ات، Evil Twin | ❌ بدون root (و حتی با root نیاز به درایور patched مثل nexmon) |

پس منطقی‌ترین سناریو: pcap را با لپ‌تاپ بگیری، به گوشی منتقل کنی و همین‌جا با منو (`4` سپس `5` یا مستقیم `5` روی فایل) بشکنی.

مسیر خروجی روی گوشی: پوشه `hunter-out` در `$HOME` (خصوصی). برای دسترسی از فایل‌منیجر:

```bash
termux-setup-storage
cp -r ~/hunter-out ~/storage/shared/
```

سرعت کرک روی گوشی پایین‌تر است (چند هسته ARM)؛ برای دیکشنری‌های بزرگ `rockyou` صبر یا hashcat لازم است.

---

## ویندوز: واقعیت‌ها

- `scan`, `hash`, `crack`, `report`, `keygen`, `wordlists` **بدون چیز اضافه** کار می‌کنند.
- برای مانیتور مود: Npcap را با تیک «Support raw 802.11 traffic» نصب کن + ترمینال Administrator. `doctor` وضعیت را می‌گوید.
- اگر درایورت NetMon ندارد: pcap را از گوشی/کالی بگیر و همین‌جا `hash` + `crack`.
- `deauth` روی ویندوز از مسیر Npcap تست شده.

## لینوکس

```bash
sudo ip link set wlan0 down && sudo iw wlan0 set type monitor && sudo ip link set wlan0 up
sudo python3 wifi_hunter.py sniff --iface wlan0 --monitor --seconds 60
```

---

## خروجی‌ها

```
out/  scan.json  hashes.22000  hashes.json  pot.jsonl  found.json  report.html  evil/
```

## مجوز

MIT — استفاده فقط با اجازه صاحب شبکه.
