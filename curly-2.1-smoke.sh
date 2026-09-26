#!/usr/bin/env bash
set -euo pipefail

SCRIPT="${1:-$(cd "$(dirname "$0")" && pwd)/Curly.php}"

fail() {
  echo "✗ $*" >&2
  exit 1
}

pass() {
  echo "✓ $*"
}

php -l "$SCRIPT" >/dev/null || fail "PHP syntax"
pass "PHP syntax"

version="$(php "$SCRIPT" --version)"
[[ "$version" == *"version 2.1.0"* ]] || fail "version flag"
pass "version flag"

help="$(php "$SCRIPT" --help)"
[[ "$help" == *"Usage:"* ]] || fail "help flag"
pass "help flag"

php -r '
require $argv[1];
$expected = [
    CheckStatus::OK->value,
    CheckStatus::WARNING->value,
    CheckStatus::CRITICAL->value,
    CheckStatus::UNKNOWN->value,
];
if ($expected !== [0, 1, 2, 3]) {
    fwrite(STDERR, "Unexpected CheckStatus values\n");
    exit(1);
}
$result = new CheckResult(CheckStatus::WARNING, "typed-result");
if ($result->status !== CheckStatus::WARNING || $result->message !== "typed-result") {
    fwrite(STDERR, "Unexpected CheckResult behavior\n");
    exit(1);
}
' "$SCRIPT" || fail "typed check result model"
pass "typed check result model"

for ext in curl simplexml json; do
  if ! php -m | grep -qi "^${ext}$"; then
    echo "↷ integration tests skipped: PHP extension '$ext' is not available"
    exit 0
  fi
done

TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cat > "$TMP/router.php" <<'PHP'
<?php
header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><html><body>READY READY</body></html>';
PHP

PORT="$(php -r '$s=stream_socket_server("tcp://127.0.0.1:0",$e,$es); if(!$s){exit(1);} $n=stream_socket_get_name($s,false); echo substr(strrchr($n, ":"),1); fclose($s);')"
php -S "127.0.0.1:${PORT}" "$TMP/router.php" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.3

cat > "$TMP/config.xml" <<XML
<?xml version="1.0"?>
<config>
  <testcases>
    <testcase>cases.xml</testcase>
  </testcases>
  <break_on_error>1</break_on_error>
  <logenable>1</logenable>
  <logsdir>${TMP}</logsdir>
  <logfile>curly.jsonl</logfile>
  <deletecookies>1</deletecookies>
</config>
XML

cat > "$TMP/cases.xml" <<XML
<?xml version="1.0"?>
<cases>
  <case id="1" name="homepage">
    <curl_setopt>
      <CURLOPT_URL>http://127.0.0.1:${PORT}/</CURLOPT_URL>
      <CURLOPT_HTTPHEADER>Authorization: Bearer smoke-secret|Accept: text/html</CURLOPT_HTTPHEADER>
    </curl_setopt>
    <checks>
      <status_code>
        <code>200</code>
      </status_code>
      <matchpattern>
        <pattern>/READY/</pattern>
        <source>curl</source>
      </matchpattern>
      <nomatchpattern>
        <pattern>/FAILURE/</pattern>
        <source>curl</source>
      </nomatchpattern>
      <matchpatterncount>
        <pattern>/READY/</pattern>
        <source>curl</source>
        <matchcount>2</matchcount>
      </matchpatterncount>
      <response_time>
        <time>5</time>
        <crit_time>10</crit_time>
      </response_time>
    </checks>
  </case>
</cases>
XML

set +e
output="$(cd / && php "$SCRIPT" "$TMP/config.xml" 2>&1)"
status=$?
set -e
[[ $status -eq 0 ]] || { echo "$output" >&2; fail "happy-path integration run"; }
[[ "$output" == Curly\ OK* ]] || { echo "$output" >&2; fail "Nagios OK output"; }
pass "relative testcase path + HTTP checks"

[[ -f "$TMP/curly.jsonl" ]] || fail "JSONL log creation"
if grep -q "smoke-secret" "$TMP/curly.jsonl"; then
  fail "Authorization secret leaked into JSONL log"
fi
grep -q '\*\*\*REDACTED\*\*\*' "$TMP/curly.jsonl" || fail "redaction marker absent from JSONL log"
pass "sensitive HTTP headers redacted from JSONL log"

cat > "$TMP/bad-config.xml" <<XML
<?xml version="1.0"?>
<config>
  <testcases>
    <testcase>bad-cases.xml</testcase>
  </testcases>
  <logenable>0</logenable>
</config>
XML

cat > "$TMP/bad-cases.xml" <<XML
<?xml version="1.0"?>
<cases>
  <case id="1" name="badregex">
    <curl_setopt>
      <CURLOPT_URL>http://127.0.0.1:${PORT}/</CURLOPT_URL>
    </curl_setopt>
    <checks>
      <matchpattern>
        <pattern>/[broken/</pattern>
        <source>curl</source>
      </matchpattern>
    </checks>
  </case>
</cases>
XML

set +e
bad_output="$(cd / && php "$SCRIPT" "$TMP/bad-config.xml" 2>&1)"
bad_status=$?
set -e
[[ $bad_status -eq 3 ]] || { echo "$bad_output" >&2; fail "invalid-regex exit code"; }
[[ "$bad_output" == *"not a valid PCRE pattern"* ]] || { echo "$bad_output" >&2; fail "invalid-regex diagnostic"; }
pass "invalid PCRE rejected as UNKNOWN"

echo "All Curly 2.1 smoke tests passed."
