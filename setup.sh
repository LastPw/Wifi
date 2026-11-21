#!/usr/bin/env bash
# ============================================================================
#  WiFi Hunter - one-shot installer & configurator
#  English only. Installs what exists, configures everything, verifies.
#
#  usage:
#    bash setup.sh                # standard install
#    bash setup.sh -y             # no questions
#    bash setup.sh --dry-run      # show what would run, do nothing
#    bash setup.sh --huge         # also pull rockyou/304k wordlists
#    bash setup.sh --skip-wordlists --no-scan-test
#    bash setup.sh --uninstall    # remove launcher/env we created
#
#  supported: Termux/Android, Debian/Ubuntu/Kali, Fedora, Arch, macOS, Git-Bash
# ============================================================================
set -u

APP_NAME="WiFi Hunter"
VERSION="1.0"
DRY=0
ASSUME_YES=0
HUGE=0
SKIP_WORDLISTS=0
SCAN_TEST=1
UNINSTALL=0
OUT_OVERRIDE=""

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$REPO_DIR" || exit 1

# ---------------------------------------------------------------- output ----
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'
    RED=$'\033[91m'; GRN=$'\033[92m'; YEL=$'\033[93m'; CYN=$'\033[96m'
else
    R=""; B=""; DIM=""; RED=""; GRN=""; YEL=""; CYN=""
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s %s\n' "${CYN}[*]${R}" "$*"; }
ok()   { printf '%s %s\n' "${GRN}[+]${R}" "$*"; }
warn() { printf '%s %s\n' "${YEL}[!]${R}" "$*"; }
fail() { printf '%s %s\n' "${RED}[-]${R}" "$*"; }
step() { printf '\n%s %s\n' "${B}==>${R}" "$*"; }
hr()   { printf '%s\n' "${DIM}------------------------------------------------------------------------${R}"; }

fatal() { fail "$*"; exit 1; }

run() {
    if [ "$DRY" = 1 ]; then
        printf '    %s %s\n' "${DIM}+${R}" "$*"
        return 0
    fi
    "$@"
}

run_shell() {
    if [ "$DRY" = 1 ]; then
        printf '    %s %s\n' "${DIM}+${R}" "$1"
        return 0
    fi
    sh -c "$1"
}

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    [ "$DRY" = 1 ] && return 0
    [ ! -t 0 ] && return 0
    printf '%s [y/N] ' "$1"
    read -r answer
    case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) ASSUME_YES=1 ;;
        --dry-run) DRY=1 ;;
        --huge) HUGE=1 ;;
        --skip-wordlists) SKIP_WORDLISTS=1 ;;
        --no-scan-test) SCAN_TEST=0 ;;
        --uninstall) UNINSTALL=1 ;;
        --out) shift; OUT_OVERRIDE="${1:-}" ;;
        -h|--help) usage ;;
        *) warn "unknown option: $1"; usage ;;
    esac
    shift
done

# ------------------------------------------------------------- detection ----
ENV_KIND="unknown"
if [ -n "${TERMUX_VERSION:-}" ] || printf '%s' "${PREFIX:-}" | grep -q 'com\.termux'; then
    ENV_KIND="termux"
else
    case "$(uname -s 2>/dev/null)" in
        Linux) ENV_KIND="linux" ;;
        Darwin) ENV_KIND="macos" ;;
        MINGW*|MSYS*|CYGWIN*) ENV_KIND="windows" ;;
        *) ENV_KIND="unknown" ;;
    esac
fi

PY="python"
have python3 && PY="python3"
have python && PY="python"

ENV_FILE="$HOME/.wifihunter/env"
DEFAULT_OUT="$REPO_DIR/hunter-out"

say ""
say "${B}${APP_NAME} installer v${VERSION}${R}"
say "repo    : $REPO_DIR"
say "env     : $ENV_KIND"
say "python  : $(command -v "$PY" 2>/dev/null || echo 'not found')"
[ "$DRY" = 1 ] && say "mode    : ${YEL}dry-run (nothing will change)${R}"
hr

# ------------------------------------------------------------- uninstall ----
if [ "$UNINSTALL" = 1 ]; then
    step "removing installer artifacts"
    for f in "$HOME/.local/bin/wh" "${PREFIX:-}/bin/wh"; do
        if [ -f "$f" ] && grep -q "wifihunter-launcher" "$f" 2>/dev/null; then
            run rm -f "$f"; ok "removed $f"
        fi
    done
    if [ -f "$HOME/.bashrc" ] && grep -q "wifihunter/env" "$HOME/.bashrc" 2>/dev/null; then
        run_shell "grep -v 'wifihunter' '$HOME/.bashrc' > '$HOME/.bashrc.tmp' && mv '$HOME/.bashrc.tmp' '$HOME/.bashrc'"
        ok "cleaned ~/.bashrc"
    fi
    run rm -rf "$HOME/.wifihunter"
    ok "done (repo and wordlists kept)"
    exit 0
fi

# ------------------------------------------------------------- packages ----
linux_install() {  # package
    case "${SUDO_PKG:-}" in
        pacman) exec_cmd="$SUDO_PKG -S --noconfirm --needed" ;;
        zypper) exec_cmd="$SUDO_PKG install -y" ;;
        "") return 1 ;;
        *) exec_cmd="$SUDO_PKG install -y" ;;
    esac
    if [ "$(id -u)" = 0 ]; then
        if [ "$DRY" = 1 ]; then printf '    %s %s %s
' "${DIM}+${R}" "$exec_cmd" "$1"; else $exec_cmd "$1" >/dev/null 2>&1; fi
    else
        if [ "$DRY" = 1 ]; then printf '    %s sudo %s %s
' "${DIM}+${R}" "$exec_cmd" "$1"; else sudo $exec_cmd "$1" >/dev/null 2>&1; fi
    fi
}

pkg_install_list() {  # name... -> best effort per package
    for p in "$@"; do
        case "$ENV_KIND" in
            termux) run pkg install -y "$p" >/dev/null 2>&1 || warn "skip: $p" ;;
            linux)  linux_install "$p" || warn "skip: $p" ;;
            macos)  run brew install "$p" >/dev/null 2>&1 || warn "skip: $p" ;;
            *) : ;;
        esac
    done
}

step "1/9 python & pip"
if [ "$ENV_KIND" = "termux" ]; then
    info "refreshing package lists"
    run pkg update -y >/dev/null 2>&1 || warn "pkg update had warnings (continuing)"
    pkg_install_list python
elif [ "$ENV_KIND" = "linux" ]; then
    if have apt-get; then SUDO_PKG=apt-get
    elif have dnf; then SUDO_PKG=dnf
    elif have pacman; then SUDO_PKG=pacman
    elif have zypper; then SUDO_PKG=zypper
    else SUDO_PKG=""
    fi
    [ -n "${SUDO_PKG:-}" ] || warn "no known package manager"
    if [ "$(id -u)" != 0 ] && ! have sudo; then warn "sudo missing - package install may fail"; fi
    pkg_install_list python3 python3-pip
fi

if ! have "$PY"; then
    fatal "python not available - install it first (Termux: pkg install python)"
fi
ok "python: $("$PY" -V 2>&1)"

run "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || warn "pip self-upgrade skipped"

step "2/9 python packages (scapy = live capture)"
if run "$PY" -m pip install scapy >/dev/null 2>&1; then
    ok "scapy installed"
else
    warn "scapy failed (optional) - retrying with --break-system-packages"
    run "$PY" -m pip install --break-system-packages scapy >/dev/null 2>&1 || warn "scapy unavailable"
fi
"$PY" -c 'import scapy' >/dev/null 2>&1 && ok "scapy import ok" || warn "scapy not importable"

step "3/9 companion tools (all optional, skipped when unavailable)"
if [ "$ENV_KIND" = "termux" ]; then
    pkg_install_list termux-api iproute2 git coreutils tsu hashcat aircrack-ng tcpdump iw reaver pixiewps hostapd dnsmasq
elif [ "$ENV_KIND" = "linux" ]; then
    pkg_install_list git aircrack-ng hashcat hcxdumptool hcxtools reaver pixiewps hostapd dnsmasq tshark iw wireless-tools tcpdump nmap
elif [ "$ENV_KIND" = "macos" ]; then
    pkg_install_list hashcat aircrack-ng tshark
elif [ "$ENV_KIND" = "windows" ]; then
    warn "windows: Npcap is required for live capture (https://npcap.com, tick 'raw 802.11')"
fi

# ------------------------------------------------------------- configure ----
step "4/9 output folder & environment"
mkdir -p "$HOME/.wifihunter" 2>/dev/null || true

if [ "$ENV_KIND" = "termux" ]; then
    if [ ! -d "$HOME/storage/shared" ]; then
        info "granting shared storage (accept the Android dialog)"
        run termux-setup-storage || warn "termux-setup-storage failed"
        sleep 3
    fi
    if [ -d "$HOME/storage/shared" ]; then
        DEFAULT_OUT="$HOME/storage/shared/WiFiHunter"
        ok "output goes to shared storage: $DEFAULT_OUT"
    else
        warn "no shared storage - output stays in $DEFAULT_OUT"
    fi
fi
[ -n "$OUT_OVERRIDE" ] && DEFAULT_OUT="$OUT_OVERRIDE"
run mkdir -p "$DEFAULT_OUT"

if [ "$DRY" = 0 ]; then
    {
        printf '# wifihunter environment (generated by setup.sh)\n'
        printf 'export HUNTER_OUT=%q\n' "$DEFAULT_OUT"
        printf 'export PYTHONUNBUFFERED=1\n'
    } > "$ENV_FILE"
else
    printf '    %s write %s\n' "${DIM}+${R}" "$ENV_FILE"
fi

if [ -f "$HOME/.bashrc" ]; then
    if ! grep -q "wifihunter/env" "$HOME/.bashrc" 2>/dev/null; then
        run_shell "printf '\n# wifihunter\n[ -f \"\$HOME/.wifihunter/env\" ] && . \"\$HOME/.wifihunter/env\"\n' >> '$HOME/.bashrc'"
        ok "~/.bashrc hooks the environment file"
    fi
fi
ok "env file: $ENV_FILE"

step "5/9 launcher"
if [ "$ENV_KIND" = "termux" ]; then
    BIN_DIR="${PREFIX:-$HOME}/bin"
elif [ "$ENV_KIND" = "linux" ] && [ "$(id -u)" = 0 ]; then
    BIN_DIR="/usr/local/bin"
elif [ "$ENV_KIND" = "linux" ] && have sudo; then
    BIN_DIR="$HOME/.local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi
run mkdir -p "$BIN_DIR"
LAUNCHER="$BIN_DIR/wh"
if [ "$DRY" = 0 ]; then
    cat > "$LAUNCHER" <<LAUNCH
#!/usr/bin/env bash
# wifihunter-launcher
export HUNTER_OUT="\${HUNTER_OUT:-$DEFAULT_OUT}"
exec "$(command -v "$PY")" "$REPO_DIR/wifi_hunter.py" "\$@"
LAUNCH
    chmod +x "$LAUNCHER"
    ok "launcher: $LAUNCHER"
else
    printf '    %s write %s\n' "${DIM}+${R}" "$LAUNCHER"
fi

step "6/9 permissions & power"
if [ "$ENV_KIND" = "termux" ]; then
    run termux-wake-lock 2>/dev/null || warn "wake-lock unavailable (install termux-api)"
    if have am; then
        run am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:com.termux.api >/dev/null 2>&1 \
            && ok "opened Termux:API settings - give it Location" \
            || warn "open Termux:API settings manually and grant Location"
    fi
else
    info "no android permissions needed on this platform"
fi

# ------------------------------------------------------------ wordlists ----
step "7/9 wordlists"
if [ "$SKIP_WORDLISTS" = 1 ]; then
    info "skipped (--skip-wordlists)"
else
    run "$PY" wifi_hunter.py wordlists build || warn "could not build curated lists"
    run "$PY" wifi_hunter.py wordlists fetch wifi || warn "could not fetch wifi lists"
    run "$PY" wifi_hunter.py wordlists fetch common-10k || warn "could not fetch common list"
    if [ "$HUGE" = 1 ]; then
        warn "downloading big lists (rockyou = ~133 MB)"
        run "$PY" wifi_hunter.py wordlists fetch huge || warn "big list download failed"
    fi
    [ "$DRY" = 0 ] && "$PY" wifi_hunter.py wordlists stats 2>/dev/null | tail -2
fi

# ---------------------------------------------------------------- verify ----
step "8/9 verification"
run "$PY" wifi_hunter.py selftest || warn "selftest reported a problem"
run "$PY" wifi_hunter.py doctor

if [ "$SCAN_TEST" = 1 ] && [ "$ENV_KIND" = "termux" ]; then
    step "9/9 live scan test"
    info "a scan needs Location permission for Termux:API and GPS on"
    if run timeout 45 "$PY" wifi_hunter.py scan --limit 8; then
        ok "scan works"
    else
        warn "scan returned nothing - check Location permission / GPS"
    fi
else
    step "9/9 done"
fi

hr
ok "installed"
say ""
say "start it:"
say "  ${B}wh${R}                 (or: cd \"$REPO_DIR\" && $PY wifi_hunter.py)"
say ""
say "output folder: $DEFAULT_OUT"
say "wordlists   : $REPO_DIR/wordlists"
say ""
if [ "$ENV_KIND" = "termux" ]; then
    say "on the phone this does: scan, pcap analysis, hash, crack, keygen, report."
    say "handshake capture needs root + a patched driver; capture on a laptop and crack here."
fi
if [ "$ENV_KIND" = "windows" ]; then
    say "windows: scan/crack/report work now; for monitor mode reinstall Npcap with"
    say "'Support raw 802.11 traffic' ticked and run from an elevated terminal."
fi
say "only test networks you are allowed to test."
say ""
