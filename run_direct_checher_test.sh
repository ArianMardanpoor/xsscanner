#!/bin/bash
# run_direct_checker_test.sh
# Runs YOUR compiled curl_reflect_checker binary directly against the exact probe URL,
# so we see precisely what it sees — no assumptions.

set -e

TARGET_DIR="${1:-.}"   # pass path to xsscanner build dir if not run from there
CHECKER="$TARGET_DIR/curl_reflect_checker"

if [ ! -x "$CHECKER" ]; then
    echo "ERROR: $CHECKER not found or not executable. Pass the build dir as arg 1."
    exit 1
fi

TESTURL='https://www.redeverdeamarela.com.br/wp-content/plugins/bvs-repasse/detalhes.php?periodo=x9canaryabc'

echo "=== Feeding exact probe URL directly into curl_reflect_checker (canary/probe mode) ==="
echo "$TESTURL" > /tmp/direct_test_urls.txt
"$CHECKER" -l /tmp/direct_test_urls.txt -c 1 -timeout 15
echo "--- (if nothing printed above, it found 0 reflections — that's the bug) ---"

echo
echo "=== Same URL, with -xss flag (break-char mode, in case canary mode regex is the issue) ==="
"$CHECKER" -l /tmp/direct_test_urls.txt -c 1 -timeout 15 -xss

echo
echo "=== Now let's see EXACTLY what curl (inside checker's own arg style) receives, manually replicated ==="
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
curl -s -L --max-time 15 -A "$UA" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -w "\nHTTPSTATUS:%{http_code}\n" \
  "$TESTURL" -o /tmp/direct_manual.html
tail -c 300 /tmp/direct_manual.html
echo
grep -o "x9canaryabc" /tmp/direct_manual.html && echo "MANUALLY CONFIRMED: canary present in body with checker's exact curl flags" || echo "NOT PRESENT with checker's exact flags — found the difference!"
