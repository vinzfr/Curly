# Curly

HTTP monitoring plugin for Nagios/Icinga, written in PHP.

Curly runs multi-step HTTP scenarios defined in XML files and outputs a standard Nagios-compatible result with performance data. It is a drop-in replacement for `check_http` when you need authenticated flows, chained requests, or pattern-based assertions, with a small runtime footprint: PHP with cURL, JSON and SimpleXML.

```
Curly OK - login=200 dashboard=200 |Curlytime=0.42;0;0;0;0 casesrun=2;0;0;0;0 ...
Curly WARNING - api matchpattern1=0 |...
Curly CRITICAL - login status_code=403 |...
```

---

## Requirements

- PHP 8.1 or later
- PHP extensions: `curl`, `json`, `simplexml`
- For the `chromium` source: Node.js + Playwright (`curly-render.js`, see below)

---

## Installation

```bash
chmod +x Curly.php
./Curly.php --version # print version (`-v` also works)
./Curly.php --help    # print usage (`-h` also works)
./Curly.php config.xml
```

In Nagios/Icinga, define a command like:

```
define command {
    command_name    check_curly
    command_line    /usr/local/lib/curly/Curly.php $ARG1$
}
```

---

## File structure

A Curly run uses two types of XML files.

The **config file** (`config.xml`) is passed on the command line. It declares global settings and the list of testcase files to run.

The **testcase files** each contain one or more HTTP request cases with their checks. Multiple testcase files run sequentially in the order they are declared. Relative testcase paths are resolved from the directory containing the main config file.

```
config.xml          ← passed to Curly.php
cases/
  01-login.xml      ← testcase file
  02-dashboard.xml  ← testcase file
```

---

## Config file reference

Root element: `<config>` or `<conf>`

```xml
<config>

  <!-- Testcase files to run (in order, no duplicates) -->
  <testcases>
    <testcase>cases/01-login.xml</testcase>
    <testcase>cases/02-dashboard.xml</testcase>
  </testcases>

  <!-- Stop after first failing case (default: 1) -->
  <break_on_error>1</break_on_error>

  <!-- Write a JSON Lines log entry per run (default: 1) -->
  <logenable>1</logenable>

  <!-- Delete the cookie temp file after each run (default: 1) -->
  <deletecookies>1</deletecookies>

  <!-- Print the internal state to stdout with sensitive values redacted (default: 0) -->
  <debug>0</debug>

  <!-- Log directory — must exist and be writable (default: /var/log/Curly) -->
  <logsdir>/var/log/Curly</logsdir>

  <!-- Log filename (default: derived from config filename, e.g. config.log) -->
  <logfile>myapp.log</logfile>

  <!-- 'long' includes check results in OK output, 'short' omits them (default: long) -->
  <output_ok_length>long</output_ok_length>

  <!-- Global cURL options applied to every case (overridable per case) -->
  <curl_setopt>
    <CURLOPT_USERAGENT>MyMonitor/1.0</CURLOPT_USERAGENT>
    <CURLOPT_CONNECTTIMEOUT>5</CURLOPT_CONNECTTIMEOUT>
    <CURLOPT_TIMEOUT>10</CURLOPT_TIMEOUT>
    <CURLOPT_SSL_VERIFYPEER>0</CURLOPT_SSL_VERIFYPEER>
  </curl_setopt>

</config>
```

The Chromium renderer path is intentionally not configurable from XML. Set the trusted process environment variable `CURLY_CHROMIUM_SCRIPT` when a path other than `/opt/curly-render.js` is required.

### Default cURL options

| Option | Default |
|---|---|
| `CURLOPT_USERAGENT` | `Curly` |
| `CURLOPT_FOLLOWLOCATION` | `1` |
| `CURLOPT_CONNECTTIMEOUT` | `10` |
| `CURLOPT_TIMEOUT` | `10` |
| `CURLOPT_VERBOSE` | `1` (captured internally) |

The following options cannot be overridden (used internally): `CURLOPT_RETURNTRANSFER`, `CURLOPT_VERBOSE`, `CURLOPT_HEADERFUNCTION`, `CURLOPT_WRITEFUNCTION`, `CURLOPT_WRITEHEADER`, `CURLOPT_READFUNCTION`, `CURLOPT_COOKIEFILE`, `CURLOPT_COOKIEJAR`, `CURLOPT_STDERR`. Curly restricts request protocols to HTTP and HTTPS.

---

## Testcase file reference

Root element: `<cases>`

Each `<case>` has a numeric `id` attribute (used for ordering) and an alphanumeric `name` attribute (used in output and perf data). Cases run in ascending `id` order.

```xml
<cases>
  <case id="1" name="login">

    <!-- cURL options for this request -->
    <curl_setopt>
      <CURLOPT_URL>https://example.com/login</CURLOPT_URL>
      <CURLOPT_POST>1</CURLOPT_POST>
      <CURLOPT_POSTFIELDS>user=admin&amp;pass=secret</CURLOPT_POSTFIELDS>
    </curl_setopt>

    <!-- One or more checks on the response -->
    <checks>
      <status_code>
        <code>200</code>
      </status_code>
      <matchpattern>
        <pattern>/Welcome/</pattern>
        <source>curl</source>
      </matchpattern>
    </checks>

  </case>
</cases>
```

### cURL options

All standard `CURLOPT_*` constants are accepted. Common ones:

| Element | Example value | Notes |
|---|---|---|
| `CURLOPT_URL` | `https://example.com/api` | **Required** |
| `CURLOPT_POST` | `1` | Enable POST |
| `CURLOPT_POSTFIELDS` | `key=value&key2=val2` | URL-encoded body |
| `CURLOPT_HTTPHEADER` | `Authorization: Bearer token\|X-Custom: val` | Multiple headers separated by `\|` |
| `CURLOPT_USERPWD` | `user:password` | Basic auth credentials |
| `CURLOPT_HTTPAUTH` | `CURLAUTH_BASIC` | Auth method constant |
| `CURLOPT_FILE` | `/tmp/download.bin` | Write response body to file |
| `CURLOPT_TIMEOUT` | `30` | Per-case timeout override |

`{get_parsepattern:...}` tokens are resolved in `CURLOPT_URL`, `CURLOPT_POSTFIELDS`, `CURLOPT_HTTPHEADER`, and any other string value before the request is made (see [parsepattern](#parsepattern) below).

---

## Check reference

Every check accepts two optional fields:

```xml
<onfail_status>WARNING</onfail_status>   <!-- WARNING or CRITICAL (default: CRITICAL) -->
<errormessage>my_custom_label</errormessage>  <!-- replaces the default failure label in output -->
```

Checks that operate on response content (`matchpattern`, `nomatchpattern`, `parsepattern`, `matchpatterncount`) require a `<source>` element. Multiple instances of the same pattern check can be defined in the same case.

---

### `status_code`

Asserts the HTTP response code. Only one per case.

```xml
<status_code>
  <code>200</code>
  <onfail_status>CRITICAL</onfail_status>
</status_code>
```

---

### `matchpattern`

Asserts that the source matches a PCRE pattern. Multiple instances allowed.

```xml
<matchpattern>
  <pattern>/csrf_token.*?value="([^"]+)"/</pattern>
  <source>curl</source>
  <onfail_status>CRITICAL</onfail_status>
  <errormessage>token_missing</errormessage>
</matchpattern>
```

**Sources:** `curl` (response body), `curlverbose` (cURL debug output including headers), `chromium` (JS-rendered DOM — see below).

---

### `nomatchpattern`

Asserts that the source does **not** match a PCRE pattern. Multiple instances allowed.

```xml
<nomatchpattern>
  <pattern>/error|exception/i</pattern>
  <source>curl</source>
</nomatchpattern>
```

---

### `parsepattern`

Extracts capture groups from the response and stores them for injection into subsequent cases via `get_parsepattern`. Multiple instances allowed, each producing one or more named values.

```xml
<parsepattern>
  <pattern>/name="csrf_token" value="([^"]+)"/</pattern>
  <source>curl</source>
</parsepattern>
```

Returns UNKNOWN if the pattern does not match or any capture group is empty.

---

### `matchpatterncount`

Asserts that a pattern matches exactly N times. Only one per case.

```xml
<matchpatterncount>
  <pattern>/<li class="item">/</pattern>
  <source>curl</source>
  <matchcount>5</matchcount>
  <onfail_status>WARNING</onfail_status>
</matchpatterncount>
```

---

### `primary_ip`

Asserts the resolved IP address of the server. Useful to verify DNS resolution or detect unexpected failovers. Only one per case.

```xml
<primary_ip>
  <ip>93.184.216.34</ip>
</primary_ip>
```

---

### `redirect_count`

Asserts the number of redirects followed. Only one per case.

```xml
<redirect_count>
  <count>2</count>
</redirect_count>
```

---

### `response_time`

Asserts total request time against warning and optional critical thresholds (in seconds). Emits Nagios performance data. Only one per case.

```xml
<response_time>
  <time>2</time>              <!-- WARNING threshold (required) -->
  <crit_time>5</crit_time>    <!-- CRITICAL threshold (optional, must be > time) -->
</response_time>
```

When `response_time` is defined, the per-case default perf data entry is replaced by the thresholded one.

Float values are supported: `<time>0.5</time>`.

---

### `md5sum`

Asserts the MD5 hash of the response body. Useful to verify that a static asset has not changed. Only one per case.

```xml
<md5sum>
  <hash>d41d8cd98f00b204e9800998ecf8427e</hash>
  <onfail_status>WARNING</onfail_status>
</md5sum>
```

---

## get_parsepattern — chaining requests

`parsepattern` stores its capture groups in a registry keyed by `file:caseid:parsepatternid:groupid`. The `get_parsepattern` token interpolates a stored value into any cURL option of a subsequent case.

```xml
<!-- Case 1: extract a CSRF token from a login form -->
<case id="1" name="login_form">
  <curl_setopt>
    <CURLOPT_URL>https://example.com/login</CURLOPT_URL>
  </curl_setopt>
  <checks>
    <parsepattern>
      <pattern>/name="csrf_token" value="([^"]+)"/</pattern>
      <source>curl</source>
    </parsepattern>
  </checks>
</case>

<!-- Case 2: POST with the extracted token -->
<case id="2" name="login_submit">
  <curl_setopt>
    <CURLOPT_URL>https://example.com/login</CURLOPT_URL>
    <CURLOPT_POST>1</CURLOPT_POST>
    <!-- file:caseid:parsepatternid:groupid -->
    <CURLOPT_POSTFIELDS>user=admin&amp;pass=secret&amp;csrf={get_parsepattern:01-login.xml:1:1:1}</CURLOPT_POSTFIELDS>
  </curl_setopt>
  <checks>
    <status_code><code>302</code></status_code>
  </checks>
</case>
```

Token format: `{get_parsepattern:FILENAME:CASEID:PARSEPATTERNID:GROUPID}`

- `FILENAME` — basename of the testcase file (e.g. `01-login.xml`)
- `CASEID` — `id` attribute of the source case
- `PARSEPATTERNID` — index of the `parsepattern` check within that case (1-based)
- `GROUPID` — capture group index (1-based)

Multiple tokens can appear in the same value.

---

## Chromium source (JS-rendered pages)

The `chromium` source runs a headless browser, waits for the page to finish loading, and passes the rendered DOM to the pattern engine. This allows checking content injected by JavaScript.

Enable it by adding `<source>chromium</source>` to any pattern check:

```xml
<matchpattern>
  <pattern>/data-loaded="true"/</pattern>
  <source>chromium</source>
</matchpattern>
```

Curly calls `node /opt/curly-render.js <URL>` by default. To use another trusted renderer path, set `CURLY_CHROMIUM_SCRIPT` in the process environment. The renderer path cannot be overridden from testcase XML. The script must print the rendered HTML to stdout and exit 0. A minimal Playwright implementation:

```js
// /opt/curly-render.js
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page    = await browser.newPage();
  await page.goto(process.argv[2], { waitUntil: 'networkidle' });
  console.log(await page.content());
  await browser.close();
})();
```

The render result is cached per case: multiple `chromium` checks in the same case only trigger one render.

If the script is not found, the check fails with UNKNOWN.

---

## Output format

Curly outputs one line to stdout in Nagios plugin format:

```
Curly {STATUS} - {check results} |{performance data}
```

Exit codes follow the Nagios convention: `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN.

**Performance data** always includes:

```
Curlytime=<total>   casestime=<sum>   casesrun=N
casesok=N   caseswarning=N   casescritical=N   casesunknown=N
checksrun=N   checksok=N   checkswarning=N   checkscritical=N   checksunknown=N
```

Each case also emits `casename=<response_time>` perf data (replaced by the thresholded entry when `response_time` check is defined).

---

## Logging

When `logenable=1`, Curly appends one JSON object per run to `<logsdir>/<logfile>` (JSON Lines format). Each entry contains the run timestamp, config path, exit status, output string, counters, and per-case check results.

```bash
# last 10 runs
tail -10 /var/log/Curly/config.log | jq '{date, status, output}'

# filter WARNING runs
grep . /var/log/Curly/config.log | jq 'select(.status == 1)'

# check results for a specific case
jq '.testcases[] | select(.casename == "login") | .checks' /var/log/Curly/config.log
```

Response body and cURL verbose output are omitted from logs by default to keep entries lean. Sensitive cURL options, authentication headers, cookies, token-like URL parameters, POST fields and parsed values are redacted from logs and debug output. Enable `debug=1` in the config to print the redacted internal state to stdout.

---

## Full example — authenticated flow

**config.xml**
```xml
<config>
  <testcases>
    <testcase>cases/auth-flow.xml</testcase>
  </testcases>
  <logsdir>/var/log/Curly</logsdir>
  <curl_setopt>
    <CURLOPT_TIMEOUT>10</CURLOPT_TIMEOUT>
    <CURLOPT_SSL_VERIFYPEER>0</CURLOPT_SSL_VERIFYPEER>
  </curl_setopt>
</config>
```

**cases/auth-flow.xml**
```xml
<cases>

  <!-- Step 1: fetch login page and extract CSRF token -->
  <case id="1" name="login_form">
    <curl_setopt>
      <CURLOPT_URL>https://app.example.com/login</CURLOPT_URL>
    </curl_setopt>
    <checks>
      <status_code><code>200</code></status_code>
      <matchpattern>
        <pattern>/name="csrf_token"/</pattern>
        <source>curl</source>
        <errormessage>csrf_form_missing</errormessage>
      </matchpattern>
      <parsepattern>
        <pattern>/name="csrf_token" value="([^"]+)"/</pattern>
        <source>curl</source>
      </parsepattern>
    </checks>
  </case>

  <!-- Step 2: POST credentials with token, expect redirect -->
  <case id="2" name="login_submit">
    <curl_setopt>
      <CURLOPT_URL>https://app.example.com/login</CURLOPT_URL>
      <CURLOPT_POST>1</CURLOPT_POST>
      <CURLOPT_POSTFIELDS>user=monitor&amp;pass=secret&amp;csrf={get_parsepattern:auth-flow.xml:1:1:1}</CURLOPT_POSTFIELDS>
    </curl_setopt>
    <checks>
      <status_code><code>302</code></status_code>
    </checks>
  </case>

  <!-- Step 3: follow redirect, verify dashboard loaded -->
  <case id="3" name="dashboard">
    <curl_setopt>
      <CURLOPT_URL>https://app.example.com/dashboard</CURLOPT_URL>
    </curl_setopt>
    <checks>
      <status_code><code>200</code></status_code>
      <matchpattern>
        <pattern>/Welcome, monitor/</pattern>
        <source>curl</source>
        <errormessage>welcome_missing</errormessage>
      </matchpattern>
      <nomatchpattern>
        <pattern>/error|exception/i</pattern>
        <source>curl</source>
      </nomatchpattern>
      <response_time>
        <time>2</time>
        <crit_time>5</crit_time>
      </response_time>
    </checks>
  </case>

</cases>
```

---

## Changelog

### v2.1

**Hardening**
- cURL and stream handles are released reliably from `finally`
- PCRE patterns are validated before execution; runtime PCRE failures report UNKNOWN
- SimpleXML is now an explicit runtime requirement and XML loading disables network access
- cURL and Chromium requests are restricted to HTTP/HTTPS
- Chromium renderer failures report UNKNOWN and rendered DOM is cached once per case
- Chromium renderer path moved from XML configuration to trusted `CURLY_CHROMIUM_SCRIPT`
- Sensitive credentials, headers, cookies, POST fields, token-like URL parameters and parsed values are redacted from debug output and JSONL logs
- JSONL writes use file locking and exception-aware JSON encoding
- Relative testcase paths are resolved from the main config file directory

**Internal refactoring**
- check outcomes use typed `CheckStatus` and `CheckResult` objects internally
- `Curly.php` can be included by tests without automatically executing the CLI entry point

### v2.0

**Bug fixes**
- `$cURL` → `$this->cURL` in `CURLOPT_HTTPAUTH` branch — auth had never been applied
- `'/.xml/'` → `'/\.xml$/'` in log filename derivation
- Duplicate `checkscritical` counter key in initialisation removed
- `count($matches[0])` on string in `nomatchpattern` → `strlen()`
- `warnTime`/`critTime` not cast to float in `response_time` check
- Loose `==` → strict `===` in `matchpatterncount`
- Redundant `assertWritableDir` call on `logsdir` removed
- `curl_close()` removed — deprecated since PHP 8.5, no-op since PHP 8.0

**New features**
- `md5sum` check — compare response body MD5 to an expected hash
- `chromium` source — run headless Playwright, pass rendered DOM to any pattern check
- `crit_time` on `response_time` — two distinct warn/crit thresholds; validated (`crit_time` must be strictly greater than `time`)

**Refactoring**
- `ExecChecks`: `switch` copy-paste ×8 replaced by `match` + `dispatchCheckResult()` (~200 lines removed)
- `CheckCases`: `validateCommonCheckArgs()` + `requireElement()` factor out repeated validation
- `loadPrefixedConstants()` replaces three separate constant-loading functions
- `assertWritableDir()` + `bail()` centralise error exits
- `resolveSource()` cleanly dispatches between `curl`, `curlverbose`, `chromium`
- `'numeric'` type added to `requireElement()` — supports float thresholds
- Logs now written as JSON Lines — one JSON object per run
- `random_bytes(8)` for cookie temp file names (replaces `rand()`)
- `errormessage` filter extended to allow spaces and dots
- PHP 8.1+ types and `str_starts_with()` used throughout
