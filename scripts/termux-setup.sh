#!/data/data/com.termux/files/usr/bin/bash
# Kept for convenience: everything lives in the main installer now.
#   bash setup.sh            (from the repo root)
exec bash "$(cd "$(dirname "$0")/.." && pwd)/setup.sh" "$@"
