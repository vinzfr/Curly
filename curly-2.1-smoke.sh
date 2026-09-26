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

$http = new HttpResult(
    body: "BODY",
    info: [
        "http_code" => 204,
        "primary_ip" => "127.0.0.1",
        "redirect_count" => 2,
        "total_time" => 0.125,
    ],
    errno: 0,
    verbose: "TRACE",
);
if (
    $http->body !== "BODY"
    || $http->source("curl") !== "BODY"
    || $http->source("curlverbose") !== "TRACE"
    || $http->httpCode() !== 204
    || $http->primaryIp() !== "127.0.0.1"
    || $http->redirectCount() !== 2
    || abs(($http->totalTime() ?? 0.0) - 0.125) > 0.000001
) {
    fwrite(STDERR, "Unexpected HttpResult behavior\n");
    exit(1);
}
$http->cacheChromium("<html>rendered</html>");
if ($http->chromium() !== "<html>rendered</html>") {
    fwrite(STDERR, "Unexpected HttpResult Chromium cache behavior\n");
    exit(1);
}

$case = new TestCaseResult("7", "typed-case");
$case->curlOptions["CURLOPT_URL"] = "https://example.invalid/";
$case->storeCheck("status_code", 0, ["status" => 0]);
if (
    $case->caseId !== "7"
    || $case->caseName !== "typed-case"
    || !$case->isOk()
    || $case->curlOptions["CURLOPT_URL"] !== "https://example.invalid/"
    || $case->checks["status_code"][0]["status"] !== 0
) {
    fwrite(STDERR, "Unexpected TestCaseResult base behavior\n");
    exit(1);
}
if ($case->recordCheck(new CheckResult(CheckStatus::WARNING, "warn=1"), false)) {
    fwrite(STDERR, "WARNING should not stop when break_on_error is disabled\n");
    exit(1);
}
if (!$case->isWarning() || $case->output(CheckStatus::WARNING) !== "warn=1 ") {
    fwrite(STDERR, "Unexpected TestCaseResult warning behavior\n");
    exit(1);
}
$unknown = new TestCaseResult("8", "unknown-case");
if (!$unknown->recordCheck(new CheckResult(CheckStatus::UNKNOWN, "unknown=1"), false)) {
    fwrite(STDERR, "UNKNOWN must stop testcase execution\n");
    exit(1);
}
if (!$unknown->isUnknown() || $unknown->output(CheckStatus::UNKNOWN) !== "unknown=1 ") {
    fwrite(STDERR, "Unexpected TestCaseResult unknown behavior\n");
    exit(1);
}
' "$SCRIPT" || fail "typed check result model"
pass "typed check, HTTP and testcase result models"

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
