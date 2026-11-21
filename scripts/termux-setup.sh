#!/data/data/com.termux/files/usr/bin/bash
# WiFi Hunter - Termux setup
# usage: bash scripts/termux-setup.sh
set -e

echo "[*] updating packages"
pkg update -y >/dev/null 2>&1 || true

echo "[*] installing python + termux-api (wifi scan bridge)"
pkg install -y python termux-api iproute2 >/dev/null

echo "[*] upgrading pip"
python -m pip install --upgrade pip >/dev/null 2>&1 || true

echo "[*] optional: scapy (pcap housekeeping, needs root for live capture)"
python -m pip install scapy >/dev/null 2>&1 || echo "    scapy failed - optional, skipping"

echo
echo "[i] IMPORTANT for scanning:"
echo "    1) install the 'Termux:API' app"
echo "    2) allow Location permission for Termux:API and turn GPS on"
echo "    3) run: termux-setup-storage     (so you can reach ~/storage/shared)"
echo
echo "[*] self test"
cd "$(dirname "$0")/.."
python wifi_hunter.py selftest

echo
echo "[+] done. start with:  python wifi_hunter.py"
echo "[i] scan: menu option 1 (backend termux-api). live capture needs root."
