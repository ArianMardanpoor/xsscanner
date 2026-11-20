#!/bin/bash
# run_with_telegram.sh — arm tg_notify (instant Telegram notification the
# moment a CONFIRMED bug is found), then run any tool of the toolchain
# normally. The wrapped tool is launched exactly as you would launch it
# yourself; nothing about the scan changes.
#
# Usage (run from the tool directory, like build.sh / the tools themselves):
#
#     ./run_with_telegram.sh -u https://target/ [xsscanner flags...]
#         → runs:  ./xsscanner -u https://target/ [flags...]
#
#     ./run_with_telegram.sh xssniper -u https://target/ [flags...]
#         → runs:  ./xssniper -u https://target/ [flags...]
#
# (The first argument is treated as a tool name only when it does not start
#  with "-"; otherwise it is forwarded to ./xsscanner.)
#
# Credentials come from .env (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID) — the
# same variables the toolchain already uses for its end-of-run log upload.

set -u

TOOL="./xsscanner"
if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
    TOOL="$1"
    shift
fi
case "$TOOL" in
    */*) ;;
    *)   TOOL="./$TOOL" ;;
esac

if [ ! -x "$TOOL" ]; then
    echo "[run_with_telegram] ERROR: $TOOL not found or not executable — build it first (bash build.sh)" >&2
    exit 1
fi

if [ ! -x "./tg_notify" ]; then
    echo "[run_with_telegram] ./tg_notify missing — building it via build_tg_notify.sh ..."
    bash "$(dirname "$0")/build_tg_notify.sh" || exit 1
fi

LOG_DIR="results"
LOG="$LOG_DIR/tg_notify.log"
mkdir -p "$LOG_DIR"
: > "$LOG"   # fresh log per run so the ARMED check below never sees a stale line

./tg_notify >> "$LOG" 2>&1 &
WPID=$!

cleanup() {
    if kill -0 "$WPID" 2>/dev/null; then
        kill "$WPID" 2>/dev/null
        wait "$WPID" 2>/dev/null
    fi
}
trap cleanup EXIT
trap 'trap - INT;  cleanup; kill -INT  $$' INT
trap 'trap - TERM; cleanup; kill -TERM $$' TERM

# Wait up to 15s for the watcher to confirm its Telegram test message was
# actually delivered (this validates the token AND the chat id before the
# scan burns hours in the background).
ARMED=0
for _ in $(seq 1 30); do
    kill -0 "$WPID" 2>/dev/null || break
    grep -q "ARMED" "$LOG" && { ARMED=1; break; }
    sleep 0.5
done

if [ "$ARMED" -eq 1 ]; then
    echo "[run_with_telegram] ✅ Telegram notifications armed — you will be pinged the moment a CONFIRMED bug is found (watcher log: $LOG)"
else
    echo "[run_with_telegram] ❌ tg_notify did NOT arm — check .env (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID) and $LOG :"
    tail -n 5 "$LOG" | sed 's/^/      /'
    if kill -0 "$WPID" 2>/dev/null; then
        echo "[run_with_telegram] starting the scan WITHOUT Telegram notifications in 5s (Ctrl-C to fix first) ..."
        sleep 5
    else
        echo "[run_with_telegram] starting the scan WITHOUT Telegram notifications ..."
    fi
fi

"$TOOL" "$@"
RC=$?
echo "[run_with_telegram] scan finished (exit $RC) — stopping tg_notify"
exit $RC
