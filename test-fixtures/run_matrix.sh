#!/usr/bin/env bash
# Scan every fixture; print a one-line verdict per file.
set -u
cd "$(dirname "$0")/.."
export CANARY_API_KEY="${CANARY_API_KEY:-$OPENROUTER_API_KEY}"
echo "fixture                                          | verdict  | mime"
echo "-------------------------------------------------|----------|----------"
for f in test-fixtures/*.txt test-fixtures/*.md test-fixtures/*.json \
         test-fixtures/*.html test-fixtures/*.csv \
         test-fixtures/*.pdf test-fixtures/*.docx \
         test-fixtures/*.jpg test-fixtures/*.zip \
         test-fixtures/*.tar.gz test-fixtures/*.bin; do
  [ -f "$f" ] || continue
  out=$(node dist/cli.js scan --file "$f" 2>/dev/null)
  status=$(printf "%s" "$out" | grep -E "^  Status:" | awk '{print $2}')
  mime=$(printf "%s" "$out" | grep -E "^  MIME:" | awk '{print $2}')
  detail=$(printf "%s" "$out" | grep -E "^  Detail:" | head -1 | sed 's/^  Detail:[ ]*//')
  printf "%-48s | %-8s | %s\n" "$(basename "$f")" "${status:-?}" "${mime:-?}"
  if [ -n "$detail" ]; then printf "    ↳ %s\n" "$detail"; fi
done
