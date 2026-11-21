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
#    bash setup.sh --no-build     # repo packages only, do not compile
#    bash setup.sh --out DIR      # where output/pcap/hashes go
#    bash setup.sh --uninstall    # remove launcher/env we created
#
#  installs every requirement it can: python pkgs (scapy, pywifi), tshark,
#  dumpcap, hashcat, aircrack-ng, hcxdumptool, hcxtools, reaver, bully,
#  pixiewps, wash, hostapd, dnsmasq - from the distro repo when possible,
#  otherwise compiled from source. Termux: also installs the Termux:API app,
#  grants location, holds a wake-lock and makes an end-to-end test scan.
#
#  supported: Termux/Android, Debian/Ubuntu/Kali, Fedora, Arch, macOS, Git-Bash
# ============================================================================
set -u

APP_NAME="WiFi Hunter"
VERSION="1.1"
DRY=0
ASSUME_YES=0
HUGE=0
SKIP_WORDLISTS=0
SCAN_TEST=1
UNINSTALL=0
OUT_OVERRIDE=""
NO_BUILD=0
BUILD_DEPS_DONE=0

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

have() { hash -r 2>/dev/null || true; command -v "$1" >/dev/null 2>&1; }

usage() {
    awk 'NR>2 && /^# =====/{exit} NR>2{sub(/^# ?/, ""); print}' "$0"
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
        --no-build) NO_BUILD=1 ;;
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

step "2/9 python bootstrap"
run "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || warn "pip upgrade skipped"
run "$PY" -m pip install --upgrade wheel setuptools >/dev/null 2>&1 || warn "wheel/setuptools skipped"
ok "pip ready"

step "3/9 requirements (python packages + cli tools)"

JOBS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
BUILD_DIR="${TMPDIR:-/tmp}/wifihunter-build"
REQ_OK=0
REQ_TOTAL=0
REQ_MISSING=""

WIN_EXTRA_PATH=""
win_refresh_path() {
    local d
    for d in "/c/Program Files/Wireshark" "/c/Program Files (x86)/Wireshark" \
             "/c/Program Files/hashcat"; do
        [ -d "$d" ] || continue
        case ":$PATH:" in *":$d:"*) continue ;; esac
        PATH="$d:$PATH"
        WIN_EXTRA_PATH="$WIN_EXTRA_PATH:$d"
    done
    export PATH
}

win_prebuilt() {  # tool: download official binary, unpack into ~/.wifihunter/tools
    local tool="$1" url="" dest f exe d
    case "$tool" in
        hashcat)     url="https://hashcat.net/files/hashcat-6.2.6.7z" ;;
        aircrack-ng) url="https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip" ;;
        *) return 1 ;;
    esac
    dest="$HOME/.wifihunter/tools"
    mkdir -p "$dest" || return 1
    f="$dest/$(basename "$url")"
    if [ ! -s "$f" ]; then
        info "downloading $tool binary"
        curl -fsSL --retry 3 --retry-all-errors --max-time 600 "$url" -o "$f" 2>/dev/null || { rm -f "$f"; return 1; }
    fi
    rm -rf "$dest/$tool"; mkdir -p "$dest/$tool"
    case "$f" in
        *.7z)  /c/Windows/System32/tar.exe -xf "$f" -C "$dest/$tool" 2>/dev/null || { rm -f "$f"; return 1; } ;;
        *.zip) unzip -qo "$f" -d "$dest/$tool" 2>/dev/null || { rm -f "$f"; return 1; } ;;
        *) return 1 ;;
    esac
    exe="$(find "$dest/$tool" -maxdepth 4 -name "$tool.exe" 2>/dev/null | head -1)"
    [ -n "$exe" ] || { rm -f "$f"; return 1; }
    d="$(dirname "$exe")"
    PATH="$d:$PATH"
    WIN_EXTRA_PATH="$WIN_EXTRA_PATH:$d"
    export PATH
    hash -r 2>/dev/null || true
}

tool_present() {
    case "$1" in
        scapy|pywifi) "$PY" -c "import $1" >/dev/null 2>&1 ;;
        *) have "$1" ;;
    esac
}

# repo package name for this platform, empty when it has to be built
pkg_name() {
    case "$ENV_KIND:$1" in
        termux:pixiewps|termux:dnsmasq) echo "$1" ;;
        termux:tshark|termux:dumpcap) echo tshark ;;
        termux:*) echo "" ;;
        windows:tshark|windows:dumpcap) echo "WiresharkFoundation.Wireshark" ;;
        windows:hashcat) echo "Hashcat.Hashcat" ;;
        windows:*) echo "" ;;
        macos:tshark|macos:dumpcap) echo wireshark ;;
        macos:aircrack-ng|macos:hashcat|macos:pixiewps|macos:bully) echo "$1" ;;
        macos:*) echo "" ;;
        linux:dumpcap) echo tshark ;;
        linux:*) echo "$1" ;;
        *) echo "" ;;
    esac
}

repo_install() {
    local pkg
    pkg="$(pkg_name "$1")"
    [ -n "$pkg" ] || return 1
    case "$ENV_KIND" in
        termux) pkg_install_list "$pkg" ;;
        linux)  linux_install "$pkg" ;;
        macos)  run brew install "$pkg" >/dev/null 2>&1 ;;
        windows) run winget install --accept-source-agreements --accept-package-agreements --silent "$pkg" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
    [ "$ENV_KIND" = "windows" ] && win_refresh_path
    tool_present "$1"
}

pip_install() {
    run "$PY" -m pip install --upgrade "$1" >/dev/null 2>&1 && return 0
    run "$PY" -m pip install --break-system-packages --upgrade "$1" >/dev/null 2>&1
}

need_build_deps() {
    [ "$BUILD_DEPS_DONE" = 1 ] && return 0
    BUILD_DEPS_DONE=1
    info "installing build toolchain (needed to compile the rest)"
    case "$ENV_KIND" in
        termux) pkg_install_list clang make autoconf automake libtool pkg-config libpcap openssl zlib libnl libcurl git wget tar ;;
        linux)  pkg_install_list build-essential libpcap-dev libssl-dev zlib1g-dev libnl-3-dev libnl-genl-3-dev libcurl4-openssl-dev git ;;
        macos)  pkg_install_list libpcap openssl libnl git ;;
    esac
}

src_build() {  # url name autotools|make
    local url="$1" name="$2" mode="$3" rc=1
    need_build_deps
    if [ "$DRY" = 1 ]; then
        printf '    %s git clone %s + make install\n' "${DIM}+${R}" "$url"
        return 0
    fi
    mkdir -p "$BUILD_DIR" || return 1
    (
        cd "$BUILD_DIR" && rm -rf "$name" || exit 1
        git clone --depth 1 "$url" "$name" >/dev/null 2>&1 || exit 1
        cd "$name" || exit 1
        if [ "$mode" = autotools ]; then
            ./autogen.sh >/dev/null 2>&1 || true
            ./configure --prefix="${PREFIX:-/usr/local}" >/dev/null 2>&1 || true
        fi
        make -j"$JOBS" >/dev/null 2>&1 || exit 1
        make install >/dev/null 2>&1 || exit 1
    ) && rc=0
    return $rc
}

build_hostapd() {
    need_build_deps
    local ver="2.11" url="https://w1.fi/releases/hostapd-2.11.tar.gz" rc=1
    if [ "$DRY" = 1 ]; then
        printf '    %s wget %s + make install\n' "${DIM}+${R}" "$url"
        return 0
    fi
    mkdir -p "$BUILD_DIR" || return 1
    (
        cd "$BUILD_DIR" && rm -rf "hostapd-$ver" || exit 1
        wget -qO- "$url" | tar xz || exit 1
        cd "hostapd-$ver" || exit 1
        cp defconfig .config || exit 1
        printf 'CONFIG_DRIVER_NL80211=y\nCONFIG_LIBNL32=y\n' >> .config
        sed -i 's/^#CONFIG_IEEE80211N/CONFIG_IEEE80211N/' .config 2>/dev/null || true
        make -j"$JOBS" hostapd >/dev/null 2>&1 || exit 1
        install -m 755 hostapd "${PREFIX:-/usr/local}/bin/hostapd" || exit 1
    ) && rc=0
    return $rc
}

# tool -> build steps
build_tool() {
    case "$1" in
        aircrack-ng) src_build https://github.com/aircrack-ng/aircrack-ng aircrack-ng autotools ;;
        hcxdumptool) src_build https://github.com/ZerBea/hcxdumptool hcxdumptool make ;;
        hcxtools)    src_build https://github.com/ZerBea/hcxtools hcxtools make ;;
        reaver)      src_build https://github.com/t6x/reaver-wps-fork-t6x reaver autotools ;;
        bully)       src_build https://github.com/aanarchyy/bully bully autotools ;;
        wash)        src_build https://github.com/t6x/reaver-wps-fork-t6x reaver autotools ;;
        hostapd)     build_hostapd ;;
        hashcat)     src_build https://github.com/hashcat/hashcat hashcat make ;;
        *) return 1 ;;
    esac
}

ensure() {  # tool
    local tool="$1"
    REQ_TOTAL=$((REQ_TOTAL + 1))
    if tool_present "$tool"; then
        REQ_OK=$((REQ_OK + 1))
        return 0
    fi
    if [ "$DRY" = 1 ]; then
        info "would install $tool"
        REQ_OK=$((REQ_OK + 1))
        case "$tool" in
            scapy|pywifi) printf '    %s pip install %s\n' "${DIM}+${R}" "$tool" ;;
            *) printf '    %s package or source build: %s\n' "${DIM}+${R}" "$tool" ;;
        esac
        return 0
    fi
    info "installing $tool"
    case "$tool" in
        pywifi)
            pip_install pywifi
            if [ "$ENV_KIND" = "windows" ]; then pip_install comtypes; fi
            ;;
        scapy) pip_install scapy ;;
        *)
            repo_install "$tool" || {
                if [ "$ENV_KIND" = "windows" ]; then
                    win_prebuilt "$tool"
                elif [ "$NO_BUILD" = 0 ]; then
                    build_tool "$tool"
                fi
            }
            ;;
    esac
    hash -r 2>/dev/null || true
    if tool_present "$tool"; then
        REQ_OK=$((REQ_OK + 1))
        ok "$tool"
        return 0
    fi
    REQ_MISSING="$REQ_MISSING $tool"
    warn "$tool: could not be installed here"
    return 1
}

# ---------------------------------------------------------- base packages --
if [ "$ENV_KIND" = "termux" ]; then
    pkg_install_list termux-api iproute2 git coreutils tsu python-numpy which procps
    pkg_install_list root-repo
    run pkg update -y >/dev/null 2>&1 || true
    pkg_install_list iw tcpdump wireless-tools wpa-supplicant
elif [ "$ENV_KIND" = "linux" ]; then
    pkg_install_list git iw wireless-tools tcpdump nmap procps
elif [ "$ENV_KIND" = "windows" ]; then
    win_refresh_path
    have winget || warn "no winget: Wireshark/hashcat must be installed by hand"
    info "windows capture also needs Npcap with raw 802.11 (https://npcap.com)"
fi

# ------------------------------------------------------------- each item ---
ensure scapy
ensure pywifi
ensure tshark
ensure dumpcap
ensure hashcat
ensure aircrack-ng
if [ "$ENV_KIND" != "windows" ]; then
    ensure hcxdumptool
    ensure hcxtools
    ensure reaver
    ensure bully
    ensure pixiewps
    ensure wash
    ensure hostapd
    ensure dnsmasq
fi

say ""
say "requirements: ${REQ_OK}/${REQ_TOTAL} ready${REQ_MISSING:+ - missing:${REQ_MISSING}}"


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
        if [ -n "$WIN_EXTRA_PATH" ]; then
            printf 'export PATH="%s:$PATH"\n' "${WIN_EXTRA_PATH#:}"
        fi
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
[ -f "$HOME/.wifihunter/env" ] && . "$HOME/.wifihunter/env"
export HUNTER_OUT="\${HUNTER_OUT:-$DEFAULT_OUT}"
exec "$(command -v "$PY")" "$REPO_DIR/wifi_hunter.py" "\$@"
LAUNCH
    chmod +x "$LAUNCHER"
    ok "launcher: $LAUNCHER"
else
    printf '    %s write %s\n' "${DIM}+${R}" "$LAUNCHER"
fi

step "6/9 android permissions (termux-api app, location, power)"

api_app_installed() {
    have pm && pm list packages 2>/dev/null | grep -q 'com\.termux\.api'
}

api_grant_location() {
    # works only when the shell may grant runtime permissions (usually needs root)
    have pm || return 1
    pm grant com.termux.api android.permission.ACCESS_FINE_LOCATION >/dev/null 2>&1 \
        || pm grant com.termux.api android.permission.ACCESS_COARSE_LOCATION >/dev/null 2>&1
}

api_install_app() {
    local dir="$HOME/.wifihunter" ver url apk
    mkdir -p "$dir"
    for ver in 1002 1001 1000 51 50; do
        apk="$dir/com.termux.api_$ver.apk"
        [ -s "$apk" ] && break
        url="https://f-droid.org/repo/com.termux.api_$ver.apk"
        info "downloading Termux:API $ver"
        curl -fsSL --max-time 120 "$url" -o "$apk" 2>/dev/null || rm -f "$apk"
        [ -s "$apk" ] && break
    done
    if [ -s "${apk:-}" ]; then
        ok "APK saved: $apk"
        if have termux-open; then
            run termux-open --content-type application/vnd.android.package-archive "$apk" \
                && ok "installer opened - tap Install, then come back" \
                || warn "open the APK manually: $apk"
        else
            warn "install it manually: $apk"
        fi
        return 0
    fi
    warn "could not download the APK"
    have termux-open-url && run termux-open-url https://f-droid.org/packages/com.termux.api/
    return 1
}

if [ "$ENV_KIND" = "termux" ]; then
    if api_app_installed; then
        ok "Termux:API app present"
    else
        warn "Termux:API app is missing - scan needs it"
        if [ "$DRY" = 1 ]; then
            printf '    %s download Termux:API from f-droid.org and install\n' "${DIM}+${R}"
        elif confirm "download and install the Termux:API app now?"; then
            api_install_app
            sleep 2
        fi
    fi

    if api_grant_location; then
        ok "location permission granted automatically"
    else
        info "grant Location to Termux:API (Android settings -> Apps -> Termux:API -> Permissions)"
        have am && run am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:com.termux.api >/dev/null 2>&1
    fi

    have termux-wake-lock && { run termux-wake-lock 2>/dev/null && ok "wake-lock held"; } \
        || warn "wake-lock unavailable"

    if [ "$DRY" = 0 ] && ! termux-wifi-scaninfo >/dev/null 2>&1; then
        info "scan is still failing - turning location services on"
        have am && run am start -a android.settings.LOCATION_SOURCE_SETTINGS >/dev/null 2>&1
        have am && run am start -a "android.settings.APPLICATION_DETAILS_SETTINGS" -d package:com.termux.api >/dev/null 2>&1
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
    scan_ok=0
    for attempt in 1 2 3; do
        if run timeout 45 "$PY" wifi_hunter.py scan --limit 8; then
            scan_ok=1
            break
        fi
        warn "attempt $attempt: no results yet"
        if [ "$attempt" = 1 ]; then
            info "granting Location and switching location services on"
            api_grant_location || true
            have am && run am start -a android.settings.LOCATION_SOURCE_SETTINGS >/dev/null 2>&1
            [ "$DRY" = 0 ] && { printf '  press enter when location is enabled... '; read -r _; }
        fi
    done
    if [ "$scan_ok" = 1 ]; then
        ok "scan works"
    else
        warn "scan still failing. checklist:"
        say "  1) Termux:API app installed?  (pkg install termux-api AND the app)"
        say "  2) Settings -> Apps -> Termux:API -> Permissions -> Location = allow"
        say "  3) Android location services switched on"
        say "  4) run: $PY wifi_hunter.py doctor"
    fi
else
    step "9/9 done"
fi

hr
if [ "$REQ_MISSING" = "" ]; then
    ok "installed - all $REQ_TOTAL requirements ready"
elif [ "$DRY" = 1 ]; then
    ok "dry-run finished (requirements would be installed)"
else
    warn "installed with $((REQ_TOTAL - REQ_OK)) missing requirement(s):$REQ_MISSING"
    if [ "$NO_BUILD" = 1 ]; then
        say "re-run without --no-build to compile them"
    else
        say "those need manual work, the rest of the tool still runs"
    fi
fi
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
