#!/bin/bash
# build_tg_notify.sh — build ONLY the add-on Telegram notifier.
#
# build.sh is intentionally left untouched (this add-on changes nothing in
# the existing toolchain); this script builds the new file on its own, using
# exactly the same per-file pattern build.sh uses for every other tool:
#
#     go build -o tg_notify tg_notify.go
set -e
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "build_tg_notify: ERROR: 'go' not found in PATH" >&2
    exit 1
fi

go build -o tg_notify tg_notify.go
echo "built ./tg_notify"
echo "next: put TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID in .env, then run: ./run_with_telegram.sh -u https://target/"
