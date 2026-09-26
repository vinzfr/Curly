#!/usr/bin/env php
<?php

/**
 * Curly - HTTP monitoring plugin for Nagios/Icinga
 * Style: Webinject (Perl) reimplemented in PHP
 *
 * Usage: ./Curly.php config.xml
 *
 * Changes vs original:
 *  - 2.1 hardening: close handles reliably with finally
 *  - 2.1 hardening: validate PCRE patterns and surface runtime PCRE errors as UNKNOWN
 *  - 2.1 hardening: require SimpleXML and use LIBXML_NONET
 *  - 2.1 hardening: restrict cURL protocols to HTTP/HTTPS
 *  - 2.1 hardening: Chromium rendering is cached and renderer failures become UNKNOWN
 *  - 2.1 hardening: Chromium renderer path comes from trusted process environment, not XML
 *  - 2.1 hardening: redact sensitive cURL options in debug output and logs
 *  - 2.1 hardening: lock JSONL writes and use JSON_THROW_ON_ERROR
 *  - 2.1 quality: resolve testcase paths relative to config.xml as a fallback
 *  - PHP 8.1+ required
 *  - Fixed $cURL → $this->cURL bug in CurlyCurlSetOpt (CURLOPT_HTTPAUTH branch)
 *  - Fixed regex '/.xml/' → '/\.xml/' in logfile derivation
 *  - Fixed missing curl_close() in closeHandles() — resource leak
 *  - Fixed count($matches[0]) on string in check_nomatchpattern → strlen()
 *  - Fixed warnTime/critTime not cast to float in check_response_time
 *  - Fixed loose == → strict === in check_matchpatterncount
 *  - Fixed redundant assertWritableDir on logsdir
 *  - Fixed $argc < 2 || $argc > 2 → count($this->argv) !== 2
 *  - Added crit_time validation in CheckCases (type + crit_time > time guard)
 *  - Added 'numeric' type in requireElement (supports float thresholds)
 *  - Extended errormessage_filter to allow spaces and dots
 *  - random_bytes() for cookie name generation
 *  - md5sum check implemented
 *  - chromium source added (JS-rendered pages via headless Node.js + Playwright)
 *  - ExecChecks duplication eliminated via dispatchCheckResult()
 *  - CheckCases validation duplication eliminated via validateCommonCheckArgs()
 *  - Root node validation added in LoadXmlCnf()
 *  - Logs now written as JSON Lines (one JSON object per run)
 *  - response_time supports warn/crit thresholds (warn < crit)
 *  - Minor: duplicate key 'checkscritical' removed from counters init
 */
class Curly
{
    private array $Curly = [];
    private ?\CurlHandle $cURL = null;
    private array $argv = [];
    private string $xmlconfig = '';
    private mixed $CurlOptStdErrHandle = false;
    private mixed $CurlOptFileHandle = false;

    // ─────────────────────────────────────────────
    //  Entry point
    // ─────────────────────────────────────────────

    public function CurlyExec(array $argv): void
    {
        $this->argv = $argv;
        $this->LoadDefaultCnf();
        $this->CurlyPreChecks();
        $this->LoadXmlCnf();
        $this->cookies();
        $this->RunTestCases();
        $this->endtasks();

        if ($this->Curly['conf']['debug'] === 1) {
            print_r($this->redactSensitiveData($this->Curly));
        }

        echo $this->Curly['result']['output']['stdout'] . PHP_EOL;
        exit($this->Curly['result']['exit_status']);
    }

    // ─────────────────────────────────────────────
    //  Configuration
    // ─────────────────────────────────────────────

    private function LoadDefaultCnf(): void
    {
        $this->Curly['conf'] = [
            'testcases'            => [],
            'exit_codes'           => [
                'UNKNOWN'  => 3,
                'OK'       => 0,
                'WARNING'  => 1,
                'CRITICAL' => 2,
            ],
            'curl_setopt'          => [
                'CURLOPT_RETURNTRANSFER' => 1,
                'CURLOPT_USERAGENT'      => 'Curly',
                'CURLOPT_VERBOSE'        => 1,
                'CURLOPT_FOLLOWLOCATION' => 1,
                'CURLOPT_CONNECTTIMEOUT' => 10,
                'CURLOPT_TIMEOUT'        => 10,
                'CURLOPT_PROTOCOLS'      => (defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS'))
                    ? CURLPROTO_HTTP | CURLPROTO_HTTPS
                    : 3,
                'CURLOPT_REDIR_PROTOCOLS'=> (defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS'))
                    ? CURLPROTO_HTTP | CURLPROTO_HTTPS
                    : 3,
                'CURLOPT_STDERR'         => 'php://memory',
                'CURLOPT_COOKIEFILE'     => '',
                'CURLOPT_COOKIEJAR'      => '',
            ],
            // These cannot be overridden by XML config
            'curl_setopt_deny'     => [
                'CURLOPT_RETURNTRANSFER',
                'CURLOPT_VERBOSE',
                'CURLOPT_HEADERFUNCTION',
                'CURLOPT_WRITEFUNCTION',
                'CURLOPT_WRITEHEADER',
                'CURLOPT_READFUNCTION',
                'CURLOPT_COOKIEFILE',
                'CURLOPT_COOKIEJAR',
                'CURLOPT_STDERR',
                'CURLOPT_PROTOCOLS',
                'CURLOPT_REDIR_PROTOCOLS',
            ],
            'case_name_filter'     => '/^[a-zA-Z0-9_-]+$/',
            'errormessage_filter'  => '/^[a-zA-Z0-9_\-\. ]+$/',
            'flags_ok'             => [0, 1],
            'debug'                => 0,
            'break_on_error'       => 1,
            'logenable'            => 1,
            'logfile'              => 'Curly.log',
            'deletecookies'        => 1,
            'cookiesdir'           => '/tmp',
            'output_ok_length'     => 'long',
            'logsdir'              => '/var/log/Curly',
            'chromium_script'      => getenv('CURLY_CHROMIUM_SCRIPT') ?: '/opt/curly-render.js',
            'checks'               => [
                'status_code',
                'matchpattern',
                'nomatchpattern',
                'matchpatterncount',
                'parsepattern',
                'primary_ip',
                'redirect_count',
                'response_time',
                'md5sum',
            ],
        ];

        $this->Curly['version']             = '2.1.0';
        $this->Curly['curlopt_constants']   = $this->loadPrefixedConstants('CURLOPT_');
        $this->Curly['curlauth_constants']  = $this->loadPrefixedConstants('CURLAUTH_');
        $this->Curly['curlinfo_constants']  = $this->loadPrefixedConstants('CURLINFO_');
        $this->Curly['parsepattern_results'] = [];
        $this->Curly['result'] = [
            'output'   => [
                'UNKNOWN'   => '',
                'OK'        => '',
                'WARNING'   => '',
                'CRITICAL'  => '',
                'perfdatas' => '',
                'stdout'    => '',
            ],
            'counters' => [
                'CurlyStartTime'  => microtime(true),
                'CurlyEndTime'    => 0,
                'CurlyTime'       => 0,
                'casesrun'        => 0,
                'casestime'       => 0,
                'casesok'         => 0,
                'casescritical'   => 0,
                'caseswarning'    => 0,
                'casesunknown'    => 0,
                'checksrun'       => 0,
                'checksok'        => 0,
                'checkscritical'  => 0,
                'checkswarning'   => 0,
                'checksunknown'   => 0,
            ],
            'exit_status' => 0,
            'testcases'   => [],
        ];
    }

    /** Return all PHP constants whose name starts with $prefix */
    private function loadPrefixedConstants(string $prefix): array
    {
        $result = [];
        foreach (get_defined_constants() as $name => $val) {
            if (str_starts_with($name, $prefix)) {
                $result[$name] = $val;
            }
        }
        return $result;
    }

    // ─────────────────────────────────────────────
    //  Pre-flight checks
    // ─────────────────────────────────────────────

    private function CurlyPreChecks(): void
    {
        if (count($this->argv) !== 2) {
            $this->bail('Usage: ' . $this->argv[0] . ' config.xml');
        }

        $arg = $this->argv[1];

        if ($arg === '-h' || $arg === '--help') {
            echo 'Usage: ' . $this->argv[0] . ' config.xml' . PHP_EOL;
            exit($this->Curly['conf']['exit_codes']['OK']);
        }
        if ($arg === '-v' || $arg === '--version') {
            echo $this->argv[0] . ' version ' . $this->Curly['version'] . PHP_EOL;
            exit($this->Curly['conf']['exit_codes']['OK']);
        }

        if (version_compare(PHP_VERSION, '8.1.0', '<')) {
            $this->bail('PHP version >= 8.1.0 required - current: ' . PHP_VERSION);
        }
        if (!extension_loaded('curl')) {
            $this->bail('PHP cURL extension not loaded');
        }
        if (!extension_loaded('json')) {
            $this->bail('PHP json extension not loaded');
        }
        if (!extension_loaded('simplexml')) {
            $this->bail('PHP SimpleXML extension not loaded');
        }

        if (!is_file($arg)) {
            $this->bail('File ' . $arg . ' not found');
        }
        if (!is_readable($arg)) {
            $this->bail('File ' . $arg . ' not readable');
        }

        $resolved = realpath($arg);
        $this->xmlconfig = $resolved !== false ? $resolved : $arg;
    }

    // ─────────────────────────────────────────────
    //  XML config loader
    // ─────────────────────────────────────────────

    private function LoadXmlCnf(): void
    {
        $XmlCnfRaw = simplexml_load_file($this->xmlconfig, null, LIBXML_NOCDATA | LIBXML_NONET);
        if (!$XmlCnfRaw) {
            $this->bail('Failed loading ' . $this->xmlconfig);
        }

        // Accept both <config> and <conf> root nodes
        $rootNode = $XmlCnfRaw->getName();
        if (!in_array($rootNode, ['config', 'conf'], true)) {
            $this->bail('Root element <' . $rootNode . '> not recognized — use <config> or <conf>');
        }

        if (empty($XmlCnfRaw->testcases->testcase)) {
            $this->bail('No testcases found in ' . $this->xmlconfig);
        }

        $XmlCnf = $this->XmlToArray($XmlCnfRaw);

        // --- testcases ---
        $testcaseList = $XmlCnf['testcases']['testcase'];
        foreach ((array)$testcaseList as $testcasefile) {
            if (!is_string($testcasefile) || trim($testcasefile) === '') {
                $this->bail('Invalid testcase path in ' . $this->xmlconfig);
            }

            $testcasefile = $this->resolveTestcasePath(trim($testcasefile));
            if (in_array($testcasefile, $this->Curly['conf']['testcases'], true)) {
                $this->bail($testcasefile . ' already used');
            }
            $this->Curly['conf']['testcases'][] = $testcasefile;
        }

        // --- optional flags ---
        foreach (['break_on_error', 'logenable', 'deletecookies', 'debug'] as $flag) {
            if (isset($XmlCnf[$flag]) && in_array($XmlCnf[$flag], $this->Curly['conf']['flags_ok'], true)) {
                $this->Curly['conf'][$flag] = (int)$XmlCnf[$flag];
            }
        }

        // --- logsdir ---
        if (isset($XmlCnf['logsdir'])) {
            $dir = $XmlCnf['logsdir'];
            if (empty($dir) || is_array($dir)) {
                $this->bail('logsdir error in ' . $this->xmlconfig);
            }
            $this->Curly['conf']['logsdir'] = rtrim($dir, '/');
        }
        if ($this->Curly['conf']['logenable']) {
            $this->assertWritableDir($this->Curly['conf']['logsdir']);
        }

        // --- output_ok_length ---
        if (isset($XmlCnf['output_ok_length']) && in_array($XmlCnf['output_ok_length'], ['short', 'long'], true)) {
            $this->Curly['conf']['output_ok_length'] = $XmlCnf['output_ok_length'];
        }

        // --- logfile ---
        if (isset($XmlCnf['logfile'])) {
            $lf = $XmlCnf['logfile'];
            if (empty($lf) || is_array($lf) || preg_match('/\//', $lf)) {
                $this->bail('logfile error in ' . $this->xmlconfig);
            }
            $this->Curly['conf']['logfile'] = $lf;
        } else {
            // Derive logfile name from config filename — fix: escape the dot
            $this->Curly['conf']['logfile'] = preg_replace('/\.xml$/', '.log', basename($this->xmlconfig));
        }

        // --- global curl_setopt overrides ---
        if (isset($XmlCnf['curl_setopt']) && is_array($XmlCnf['curl_setopt'])) {
            foreach ($XmlCnf['curl_setopt'] as $opt => $val) {
                if (
                    !is_array($opt) && !is_array($val)
                    && !in_array($opt, $this->Curly['conf']['curl_setopt_deny'], true)
                    && isset($this->Curly['curlopt_constants'][$opt])
                ) {
                    $this->Curly['conf']['curl_setopt'][$opt] = $val;
                }
            }
        }

        // --- chromium renderer path ---
        // The executable script path is intentionally not configurable from XML:
        // config/testcase files may be less trusted than the process environment.
        // Use CURLY_CHROMIUM_SCRIPT=/path/to/curly-render.js when an override is needed.
        if (isset($XmlCnf['chromium_script']) && trim((string)$XmlCnf['chromium_script']) !== '') {
            $requested = trim((string)$XmlCnf['chromium_script']);
            if ($requested !== $this->Curly['conf']['chromium_script']) {
                $this->bail(
                    'chromium_script can no longer be overridden from XML; use CURLY_CHROMIUM_SCRIPT instead'
                );
            }
        }
    }

    private function resolveTestcasePath(string $testcasefile): string
    {
        if (is_file($testcasefile)) {
            $resolved = realpath($testcasefile);
            return $resolved !== false ? $resolved : $testcasefile;
        }

        $isAbsolute = str_starts_with($testcasefile, '/')
            || preg_match('/^[A-Za-z]:[\\\\\/]/', $testcasefile) === 1;

        if (!$isAbsolute) {
            $candidate = dirname($this->xmlconfig) . DIRECTORY_SEPARATOR . $testcasefile;
            if (is_file($candidate)) {
                $resolved = realpath($candidate);
                return $resolved !== false ? $resolved : $candidate;
            }
        }

        return $testcasefile;
    }

    // ─────────────────────────────────────────────
    //  Cookie temp file setup
    // ─────────────────────────────────────────────

    private function cookies(): void
    {
        $this->assertWritableDir($this->Curly['conf']['cookiesdir']);
        // Use random_bytes instead of rand() for unpredictable filenames
        $token = bin2hex(random_bytes(8));
        $base  = $this->Curly['conf']['cookiesdir'] . '/Curly_' . $token;
        $this->Curly['conf']['curl_setopt']['CURLOPT_COOKIEFILE'] = $base . '.cookie';
        $this->Curly['conf']['curl_setopt']['CURLOPT_COOKIEJAR']  = $base . '.jar';
    }

    // ─────────────────────────────────────────────
    //  Test case runner
    // ─────────────────────────────────────────────

    private function RunTestCases(): void
    {
        foreach ($this->Curly['conf']['testcases'] as $testcasefile) {
            $cases        = $this->LoadXmlTestCase($testcasefile);
            $testcasefile = basename($testcasefile);
            $cases        = $this->LoadCases($testcasefile, $cases);

            foreach ($cases as $casekey => $case) {
                $casename = $case['@attributes']['name'] . ' ';
                $this->RunCase($testcasefile, $casekey, $case);
                $tc = $this->Curly['result']['testcases'][$testcasefile][$casekey];

                if ($tc['is_unknown']) {
                    $this->Curly['result']['counters']['casesunknown']++;
                    $this->Curly['result']['output']['UNKNOWN'] .= $casename . $tc['output_unknown'];
                    return;
                } elseif ($tc['is_critical']) {
                    $this->Curly['result']['counters']['casescritical']++;
                    $this->Curly['result']['output']['CRITICAL'] .= $casename . $tc['output_critical'];
                    if ($this->Curly['conf']['break_on_error']) {
                        return;
                    }
                } elseif ($tc['is_warning']) {
                    $this->Curly['result']['counters']['caseswarning']++;
                    $this->Curly['result']['output']['WARNING'] .= $casename . $tc['output_warning'];
                    if ($this->Curly['conf']['break_on_error']) {
                        return;
                    }
                } else {
                    $this->Curly['result']['counters']['casesok']++;
                    $this->Curly['result']['output']['OK'] .= $casename . $tc['output_ok'];
                }
            }
        }
    }

    private function LoadXmlTestCase(string $testcasefile): \SimpleXMLElement
    {
        $cases = simplexml_load_file($testcasefile, null, LIBXML_NOCDATA | LIBXML_NONET);
        if (!$cases) {
            $this->bail('Failed loading ' . $testcasefile);
        }
        return $cases;
    }

    private function LoadCases(string $testcasefile, \SimpleXMLElement $cases): array
    {
        $this->CheckCases($testcasefile, $cases);
        $casesArr   = $this->XmlToArray($cases);
        $sortcases  = [];

        if (isset($casesArr['case']['@attributes'])) {
            // Single case
            $sortcases[] = $casesArr['case'];
        } else {
            // Multiple cases — sort by id attribute
            $attributeids = array_column(
                array_map(fn($c) => $c['@attributes'], $casesArr['case']),
                'id'
            );
            asort($attributeids);
            foreach (array_keys($attributeids) as $idx) {
                $sortcases[] = $casesArr['case'][$idx];
            }
        }

        // Normalise check arrays to uniform depth
        // Normalise every check to an array-of-instances: [ 0 => [...], 1 => [...] ]
        // After XmlToArray, a single instance arrives as an assoc array ['code'=>'200',...]
        // while multiple instances arrive as [ 0 => [...], 1 => [...] ].
        // We detect this by checking whether the first key is a string (single) or int (multi).
        foreach ($sortcases as $key => $val) {
            foreach ($val['checks'] as $check => $arg) {
                if (!is_array($arg)) {
                    continue;
                }
                $firstKey = array_key_first($arg);
                if (is_string($firstKey)) {
                    // Single instance — wrap it
                    $sortcases[$key]['checks'][$check] = [$arg];
                }
                // Otherwise already [ 0 => [...], 1 => [...] ] — nothing to do
            }
        }

        return $sortcases;
    }

    // ─────────────────────────────────────────────
    //  XML validation
    // ─────────────────────────────────────────────

    private function CheckCases(string $testcasefile, \SimpleXMLElement $cases): void
    {
        $prefix         = 'Curly UNKNOWN - ' . $testcasefile . ' - ';
        $sources_ok     = ['curl', 'curlverbose', 'chromium'];
        $onfail_ok      = ['WARNING', 'CRITICAL'];
        $check_caseids  = [];
        $check_casenames = [];

        if ($cases->getName() !== 'cases') {
            $this->bail('Root element <' . $cases->getName() . '> not recognized — use <cases>', $prefix);
        }
        if (!isset($cases->case)) {
            $this->bail('No case found', $prefix);
        }

        foreach ($cases->case as $case) {
            // --- id ---
            if (empty($case->attributes()->id)) {
                $this->bail('A case id attribute is missing', $prefix);
            }
            if (!preg_match('/^[0-9]+$/', $case->attributes()->id)) {
                $this->bail('Case ' . $case->attributes()->id . ' - id not an integer', $prefix);
            }
            $caseid = (int)$case->attributes()->id;
            if (in_array($caseid, $check_caseids, true)) {
                $this->bail('Case id ' . $caseid . ' is already used', $prefix);
            }
            $check_caseids[] = $caseid;

            // --- name ---
            if (empty($case->attributes()->name)) {
                $this->bail('Case ' . $caseid . ' - name attribute missing', $prefix);
            }
            $casename = (string)$case->attributes()->name;
            if (!preg_match($this->Curly['conf']['case_name_filter'], $casename)) {
                $this->bail('Case ' . $caseid . ' - name format invalid: ' . $casename, $prefix);
            }
            if (in_array($casename, $check_casenames, true)) {
                $this->bail('Case ' . $caseid . ' - name "' . $casename . '" already used', $prefix);
            }
            $check_casenames[] = $casename;

            // --- structure ---
            if (count($case->children()) === 0) {
                $this->bail('Case ' . $caseid . ' - no XML elements found', $prefix);
            }
            if (empty($case->curl_setopt)) {
                $this->bail('Case ' . $caseid . ' - curl_setopt element not found', $prefix);
            }
            if (empty($case->curl_setopt->CURLOPT_URL)) {
                $this->bail('Case ' . $caseid . ' - CURLOPT_URL element not found', $prefix);
            }
            if (empty($case->checks) || count($case->checks->children()) === 0) {
                $this->bail('Case ' . $caseid . ' - no checks defined', $prefix);
            }

            // --- per-check validation ---
            // Checks that may only appear once
            $unique = ['status_code' => [], 'primary_ip' => [], 'redirect_count' => [], 'response_time' => [], 'md5sum' => []];

            foreach ($case->checks->children() as $checkname => $checkarg) {
                $checkname = trim($checkname);

                if (!in_array($checkname, $this->Curly['conf']['checks'], true)) {
                    $this->bail('Case ' . $caseid . ' - unknown check: ' . $checkname, $prefix);
                }

                // Uniqueness guard for scalar checks
                if (isset($unique[$checkname])) {
                    if (in_array($checkname, $unique[$checkname], true)) {
                        $this->bail('Case ' . $caseid . ' - ' . $checkname . ' already defined', $prefix);
                    }
                    $unique[$checkname][] = $checkname;
                }

                // Type-specific required fields
                switch ($checkname) {
                    case 'status_code':
                        $this->requireElement($checkarg, 'code', $caseid, $checkname, $prefix, 'integer');
                        break;
                    case 'primary_ip':
                        $this->requireElement($checkarg, 'ip', $caseid, $checkname, $prefix);
                        break;
                    case 'redirect_count':
                        $this->requireElement($checkarg, 'count', $caseid, $checkname, $prefix, 'integer');
                        break;
                    case 'response_time':
                        $this->requireElement($checkarg, 'time', $caseid, $checkname, $prefix, 'numeric');
                        if (isset($checkarg->crit_time)) {
                            $wt = (float)(string)$checkarg->time;
                            $ct = (float)(string)$checkarg->crit_time;
                            if (!preg_match('/^[0-9]+(\.[0-9]+)?$/', (string)$checkarg->crit_time)) {
                                $this->bail('Case ' . $caseid . ' - response_time - <crit_time> must be a number', $prefix);
                            }
                            if ($ct <= $wt) {
                                $this->bail('Case ' . $caseid . ' - response_time - crit_time must be > time', $prefix);
                            }
                        }
                        break;
                    case 'md5sum':
                        $this->requireElement($checkarg, 'hash', $caseid, $checkname, $prefix);
                        if (!preg_match('/^[a-f0-9]{32}$/i', (string)$checkarg->hash)) {
                            $this->bail('Case ' . $caseid . ' - md5sum - hash must be a valid MD5 hex string', $prefix);
                        }
                        break;
                    case 'matchpatterncount':
                        $this->requireElement($checkarg, 'pattern',    $caseid, $checkname, $prefix, 'regex');
                        $this->requireElement($checkarg, 'source',     $caseid, $checkname, $prefix, 'source', $sources_ok);
                        $this->requireElement($checkarg, 'matchcount', $caseid, $checkname, $prefix, 'integer');
                        break;
                    default:
                        // matchpattern / nomatchpattern / parsepattern
                        $this->requireElement($checkarg, 'pattern', $caseid, $checkname, $prefix, 'regex');
                        $this->requireElement($checkarg, 'source',  $caseid, $checkname, $prefix, 'source', $sources_ok);
                        break;
                }

                // Common optional fields
                $this->validateCommonCheckArgs($checkarg, $caseid, $checkname, $prefix, $onfail_ok);
            }
        }
    }

    /**
     * Validate that a required child element exists and optionally matches a type.
     * $type: 'integer' | 'regex' | 'source' | '' (any non-empty string)
     */
    private function requireElement(
        \SimpleXMLElement $checkarg,
        string $field,
        int $caseid,
        string $checkname,
        string $prefix,
        string $type = '',
        array $allowedValues = []
    ): void {
        if (empty($checkarg->$field)) {
            $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - <' . $field . '> element required', $prefix);
        }
        if (count($checkarg->$field) !== 1) {
            $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - only one <' . $field . '> allowed', $prefix);
        }
        $val = trim((string)$checkarg->$field);
        switch ($type) {
            case 'integer':
                if (!preg_match('/^[0-9]+$/', $val)) {
                    $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - <' . $field . '> must be an integer, got: ' . $val, $prefix);
                }
                break;
            case 'numeric':
                if (!preg_match('/^[0-9]+(\.[0-9]+)?$/', $val)) {
                    $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - <' . $field . '> must be a number, got: ' . $val, $prefix);
                }
                break;
            case 'regex':
                if (!str_starts_with($val, '/')) {
                    $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - <' . $field . '> must include delimiters (e.g. /pattern/), got: ' . $val, $prefix);
                }
                if (@preg_match($val, '') === false) {
                    $this->bail(
                        'Case ' . $caseid . ' - ' . $checkname . ' - <' . $field
                        . '> is not a valid PCRE pattern: ' . preg_last_error_msg(),
                        $prefix
                    );
                }
                break;
            case 'source':
                if (!in_array($val, $allowedValues, true)) {
                    $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - <source> must be one of: ' . implode(', ', $allowedValues), $prefix);
                }
                break;
        }
    }

    /** Validate optional onfail_status and errormessage fields (shared by all check types) */
    private function validateCommonCheckArgs(
        \SimpleXMLElement $checkarg,
        int $caseid,
        string $checkname,
        string $prefix,
        array $onfail_ok
    ): void {
        if (isset($checkarg->onfail_status)) {
            $status = trim((string)$checkarg->onfail_status);
            if (empty($status) || !in_array($status, $onfail_ok, true)) {
                $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - onfail_status must be WARNING or CRITICAL', $prefix);
            }
        }
        if (isset($checkarg->errormessage)) {
            $msg = trim((string)$checkarg->errormessage);
            if (!preg_match($this->Curly['conf']['errormessage_filter'], $msg)) {
                $this->bail('Case ' . $caseid . ' - ' . $checkname . ' - errormessage format invalid', $prefix);
            }
        }
    }

    // ─────────────────────────────────────────────
    //  Case execution
    // ─────────────────────────────────────────────

    private function RunCase(string $testcasefile, int $casekey, array $case): void
    {
        $caseid   = $case['@attributes']['id'];
        $casename = $case['@attributes']['name'];

        $this->Curly['result']['counters']['casesrun']++;
        $tc = &$this->Curly['result']['testcases'][$testcasefile][$casekey];
        $tc = [
            'caseid'          => $caseid,
            'casename'        => $casename,
            'is_warning'      => 0,
            'is_critical'     => 0,
            'is_unknown'      => 0,
            'output_ok'       => '',
            'output_warning'  => '',
            'output_critical' => '',
            'output_unknown'  => '',
            'curl_setopt'     => [],
            'curl_getinfo'    => [],
            'checks'          => [],
            'curl'            => '',
            'curlverbose'     => '',
        ];

        $handle = curl_init();
        if ($handle === false) {
            $tc['is_unknown'] = 1;
            $tc['output_unknown'] = 'curl_init failed';
            return;
        }

        $this->cURL = $handle;

        try {
            $this->CurlyCurlSetOpt($testcasefile, $casekey, $case, $caseid);

            if ($tc['is_unknown']) {
                $tc['curl'] = 'CurlyCurlSetOpt failed';
                $tc['curlverbose'] = 'CurlyCurlSetOpt failed';
                return;
            }

            $cURLExec           = curl_exec($this->cURL);
            $tc['curl_errno']   = curl_errno($this->cURL);
            $tc['curl_getinfo'] = curl_getinfo($this->cURL);

            $casetime = round((float)($tc['curl_getinfo']['total_time'] ?? 0), 4);
            $this->Curly['result']['counters']['casestime'] += $casetime;

            if (!isset($case['checks']['response_time'])) {
                $this->Curly['result']['output']['perfdatas'] .= $casename . '=' . $casetime . ';0;0;0;0 ';
            }

            if (is_resource($this->CurlOptFileHandle)) {
                fclose($this->CurlOptFileHandle);
                $this->CurlOptFileHandle = false;
            }

            if (is_resource($this->CurlOptStdErrHandle)) {
                rewind($this->CurlOptStdErrHandle);
                $tc['curlverbose'] = stream_get_contents($this->CurlOptStdErrHandle) ?: '';
                fclose($this->CurlOptStdErrHandle);
                $this->CurlOptStdErrHandle = false;
            }

            if ($cURLExec === false) {
                $tc['is_unknown']     = 1;
                $tc['curl']           = curl_error($this->cURL);
                $tc['output_unknown'] = $tc['curl'] !== '' ? $tc['curl'] : 'curl_exec failed';
                return;
            }

            $tc['curl'] = $cURLExec;
            $this->ExecChecks($testcasefile, $casekey, $case, $caseid);
        } finally {
            $this->closeHandles();
        }
    }

    private function closeHandles(): void
    {
        if (is_resource($this->CurlOptStdErrHandle)) {
            fclose($this->CurlOptStdErrHandle);
            $this->CurlOptStdErrHandle = false;
        }
        if (is_resource($this->CurlOptFileHandle)) {
            fclose($this->CurlOptFileHandle);
            $this->CurlOptFileHandle = false;
        }
        if ($this->cURL !== null) {
            @curl_close($this->cURL);
            $this->cURL = null;
        }
    }

    private function CurlyCurlSetOpt(string $testcasefile, int $casekey, array $case, $caseid): void
    {
        $this->CurlOptStdErrHandle = false;
        $this->CurlOptFileHandle   = false;
        $tc = &$this->Curly['result']['testcases'][$testcasefile][$casekey];

        // Apply global defaults
        foreach ($this->Curly['conf']['curl_setopt'] as $opt => $val) {
            if (!isset($this->Curly['curlopt_constants'][$opt])) {
                $tc['is_unknown']     = 1;
                $tc['output_unknown'] = 'Unsupported cURL option: ' . $opt;
                return;
            }

            $tc['curl_setopt'][$opt] = $val;

            if ($opt === 'CURLOPT_STDERR') {
                $this->CurlOptStdErrHandle = fopen((string)$val, 'w+');
                if (!is_resource($this->CurlOptStdErrHandle)) {
                    $tc['is_unknown']     = 1;
                    $tc['output_unknown'] = $opt . ' - ' . $val . ' fopen failed';
                    return;
                }
                if (!$this->setCurlOption($testcasefile, $casekey, $opt, $this->CurlOptStdErrHandle)) {
                    return;
                }
            } elseif ($opt === 'CURLOPT_HTTPHEADER') {
                $headers = is_array($val) ? $val : explode('|', (string)$val);
                if (!$this->setCurlOption($testcasefile, $casekey, $opt, $headers)) {
                    return;
                }
            } else {
                if (!$this->setCurlOption($testcasefile, $casekey, $opt, $val)) {
                    return;
                }
            }
        }

        // Apply case-level overrides
        foreach ($case['curl_setopt'] as $opt => $val) {
            if (!isset($this->Curly['curlopt_constants'][$opt])) {
                continue;
            }
            if (in_array($opt, $this->Curly['conf']['curl_setopt_deny'], true)) {
                continue;
            }

            // Resolve get_parsepattern tokens in values
            if (is_string($val) && preg_match_all('/{get_parsepattern:/', $val, $m)) {
                $requests = count($m[0]);
                [$val, $status, $message] = $this->get_parsepattern($testcasefile, $caseid, $opt, $val, $requests);
                if ($status === 3) {
                    $tc['is_unknown']     = 1;
                    $tc['output_unknown'] = $message;
                    return;
                }
            }

            $tc['curl_setopt'][$opt] = $val;

            if ($opt === 'CURLOPT_HTTPHEADER') {
                $headers = is_array($val) ? $val : explode('|', (string)$val);
                if (!$this->setCurlOption($testcasefile, $casekey, $opt, $headers)) {
                    return;
                }
            } elseif ($opt === 'CURLOPT_HTTPAUTH') {
                if (!isset($this->Curly['curlauth_constants'][$val])) {
                    $tc['is_unknown']     = 1;
                    $tc['output_unknown'] = $opt . ' - unknown auth method: ' . (string)$val;
                    return;
                }
                if (!$this->setCurlOption(
                    $testcasefile,
                    $casekey,
                    $opt,
                    $this->Curly['curlauth_constants'][$val]
                )) {
                    return;
                }
            } elseif ($opt === 'CURLOPT_FILE') {
                $this->CurlOptFileHandle = fopen((string)$val, 'wb');
                if (!is_resource($this->CurlOptFileHandle)) {
                    $tc['is_unknown']     = 1;
                    $tc['output_unknown'] = $opt . ' - ' . $val . ' fopen failed';
                    return;
                }
                if (!$this->setCurlOption($testcasefile, $casekey, $opt, $this->CurlOptFileHandle)) {
                    return;
                }
            } else {
                if (!$this->setCurlOption($testcasefile, $casekey, $opt, $val)) {
                    return;
                }
            }
        }
    }

    private function setCurlOption(
        string $testcasefile,
        int $casekey,
        string $opt,
        mixed $value
    ): bool {
        $tc = &$this->Curly['result']['testcases'][$testcasefile][$casekey];

        try {
            $ok = curl_setopt($this->cURL, $this->Curly['curlopt_constants'][$opt], $value);
        } catch (\Throwable $e) {
            $tc['is_unknown']     = 1;
            $tc['output_unknown'] = $opt . ' - curl_setopt failed: ' . $e->getMessage();
            return false;
        }

        if ($ok !== true) {
            $tc['is_unknown']     = 1;
            $tc['output_unknown'] = $opt . ' - curl_setopt failed';
            return false;
        }

        return true;
    }

    private function get_parsepattern(
        string $testcasefile,
        $caseid,
        string $opt,
        string $val,
        int $requests
    ): array {
        $pattern = '/{get_parsepattern:([a-zA-Z0-9_\-]+\.xml:\d+:\d+:\d+)}/';
        if (!preg_match_all($pattern, $val, $matches)) {
            return [$val, 3, 'get_parsepattern ' . $opt . ' ' . $val . ' - syntax error'];
        }

        $nbmatches = count($matches[1]);
        if ($nbmatches !== $requests) {
            return [$val, 3, 'get_parsepattern ' . $opt . ' ' . $val . ' - syntax error (count mismatch)'];
        }

        $found = 0;
        for ($i = 0; $i < $nbmatches; $i++) {
            [$ppFile, $ppCaseId, $ppId, $patternId] = explode(':', $matches[1][$i]);
            $replacement = $this->Curly['parsepattern_results'][$ppFile]['case'][$ppCaseId][$ppId][$patternId] ?? null;
            if ($replacement !== null) {
                $found++;
                $val = str_replace('{get_parsepattern:' . $matches[1][$i] . '}', $replacement, $val);
            }
        }

        if ($found !== $requests) {
            return [$val, 3, 'get_parsepattern ' . $opt . ' - found ' . $found . '/' . $requests];
        }

        return [$val, 0, 'get_parsepattern ok'];
    }

    // ─────────────────────────────────────────────
    //  Checks dispatch
    // ─────────────────────────────────────────────

    private function ExecChecks(string $testcasefile, int $casekey, array $case, $caseid): void
    {
        $parsepatternid = 0;

        foreach ($case['checks'] as $checkname => $checkarg) {
            foreach ($checkarg as $checkkey => $args) {
                $this->Curly['result']['counters']['checksrun']++;

                if ($checkname === 'parsepattern') {
                    $parsepatternid++;
                }

                try {
                    [$status, $message] = match ($checkname) {
                        'status_code'       => $this->check_statuscode($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'primary_ip'        => $this->check_primary_ip($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'redirect_count'    => $this->check_redirect_count($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'response_time'     => $this->check_response_time($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'matchpattern'      => $this->check_matchpattern($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'nomatchpattern'    => $this->check_nomatchpattern($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'parsepattern'      => $this->check_parsepattern($testcasefile, $casekey, $checkname, $checkkey, $args, $caseid, $parsepatternid),
                        'matchpatterncount' => $this->check_matchpatterncount($testcasefile, $casekey, $checkname, $checkkey, $args),
                        'md5sum'            => $this->check_md5sum($testcasefile, $casekey, $checkname, $checkkey, $args),
                        default             => [3, 'Unknown check: ' . $checkname],
                    };
                } catch (\Throwable $e) {
                    $status  = 3;
                    $message = $checkname . '=error:' . $e->getMessage();
                }

                $stop = $this->dispatchCheckResult($testcasefile, $casekey, $status, $message);
                if ($stop) {
                    return;
                }
            }
        }
    }

    /**
     * Record a check result into the right bucket and return true if execution should stop.
     */
    private function dispatchCheckResult(string $testcasefile, int $casekey, int $status, string $message): bool
    {
        $tc = &$this->Curly['result']['testcases'][$testcasefile][$casekey];

        switch ($status) {
            case 3:
                $tc['output_unknown'] .= $message . ' ';
                $tc['is_unknown'] = 1;
                $this->Curly['result']['counters']['checksunknown']++;
                return true;  // always stop on UNKNOWN

            case 2:
                $tc['output_critical'] .= $message . ' ';
                $tc['is_critical'] = 1;
                $this->Curly['result']['counters']['checkscritical']++;
                return (bool)$this->Curly['conf']['break_on_error'];

            case 1:
                $tc['output_warning'] .= $message . ' ';
                $tc['is_warning'] = 1;
                $this->Curly['result']['counters']['checkswarning']++;
                return (bool)$this->Curly['conf']['break_on_error'];

            case 0:
            default:
                $tc['output_ok'] .= $message . ' ';
                $this->Curly['result']['counters']['checksok']++;
                return false;
        }
    }

    // ─────────────────────────────────────────────
    //  Individual check implementations
    // ─────────────────────────────────────────────

    private function check_statuscode(string $f, int $k, string $name, int $ck, array $args): array
    {
        $expected = (int)$args['code'];
        $info     = $this->Curly['result']['testcases'][$f][$k]['curl_getinfo'];
        $result   = isset($info['http_code']) ? (int)$info['http_code'] : null;

        if ($result === null) {
            $status  = 3;
            $message = $name . '=unknown';
        } elseif ($result !== $expected) {
            $status  = $this->onfailStatus($args);
            $message = $name . '=' . ($args['errormessage'] ?? $result);
        } else {
            $status  = 0;
            $message = $name . '=' . $result;
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['code' => $expected, 'result' => $result ?? 'unknown', 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_primary_ip(string $f, int $k, string $name, int $ck, array $args): array
    {
        $ip     = $args['ip'];
        $info   = $this->Curly['result']['testcases'][$f][$k]['curl_getinfo'];
        $result = $info['primary_ip'] ?? 'unknown';

        if ($result === 'unknown') {
            $status  = 3;
            $message = $name . '=unknown';
        } elseif ($result !== $ip) {
            $status  = $this->onfailStatus($args);
            $message = $name . '=' . ($args['errormessage'] ?? $result);
        } else {
            $status  = 0;
            $message = $name . '=' . $result;
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['ip' => $ip, 'result' => $result, 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_redirect_count(string $f, int $k, string $name, int $ck, array $args): array
    {
        $expected = (int)$args['count'];
        $info     = $this->Curly['result']['testcases'][$f][$k]['curl_getinfo'];
        $result   = isset($info['redirect_count']) ? (int)$info['redirect_count'] : null;

        if ($result === null) {
            $status  = 3;
            $message = $name . '=unknown';
        } elseif ($result !== $expected) {
            $status  = $this->onfailStatus($args);
            $message = $name . '=' . ($args['errormessage'] ?? $result);
        } else {
            $status  = 0;
            $message = $name . '=' . $result;
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['count' => $expected, 'result' => $result ?? 'unknown', 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_response_time(string $f, int $k, string $name, int $ck, array $args): array
    {
        $info     = $this->Curly['result']['testcases'][$f][$k]['curl_getinfo'];
        $warnTime = (float)$args['time'];
        $critTime = isset($args['crit_time']) ? (float)$args['crit_time'] : null; // optional second threshold
        $result   = $info['total_time'] ?? 'unknown';

        if ($result === 'unknown') {
            $status  = 3;
            $message = $name . '=unknown';
        } else {
            $casetime = round($result, 4);
            $casename = $this->Curly['result']['testcases'][$f][$k]['casename'];

            if ($critTime !== null && $result > $critTime) {
                $status  = $this->onfailStatus($args, 2);
                $message = $name . '=' . ($args['errormessage'] ?? $result);
                $this->Curly['result']['output']['perfdatas'] .= $casename . '=' . $casetime . ';' . $warnTime . ';' . $critTime . ';0;0 ';
            } elseif ($result > $warnTime) {
                $status  = $this->onfailStatus($args, 1);
                $message = $name . '=' . ($args['errormessage'] ?? $result);
                $this->Curly['result']['output']['perfdatas'] .= $casename . '=' . $casetime . ';' . $warnTime . ';' . ($critTime ?? 0) . ';0;0 ';
            } else {
                $status  = 0;
                $message = $name . '=' . $result;
                $this->Curly['result']['output']['perfdatas'] .= $casename . '=' . $casetime . ';' . $warnTime . ';' . ($critTime ?? 0) . ';0;0 ';
            }
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['time' => $warnTime, 'result' => $result, 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_matchpattern(string $f, int $k, string $name, int $ck, array $args): array
    {
        $source  = $this->resolveSource($f, $k, $args['source']);
        $pattern = $args['pattern'];
        $match   = preg_match($pattern, $source, $matches);

        if ($match === false) {
            $status  = 3;
            $result  = '';
            $message = $name . ($ck + 1) . '=regex_error:' . preg_last_error_msg();
        } elseif ($match === 1) {
            $status  = 0;
            $result  = $matches[0];
            $message = $name . ($ck + 1) . '=' . strlen($matches[0]);
        } else {
            $result  = '';
            $status  = $this->onfailStatus($args);
            $message = $name . ($ck + 1) . '=' . ($args['errormessage'] ?? '0');
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['pattern' => $pattern, 'source' => $args['source'], 'result' => $result, 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_nomatchpattern(string $f, int $k, string $name, int $ck, array $args): array
    {
        $source  = $this->resolveSource($f, $k, $args['source']);
        $pattern = $args['pattern'];
        $match   = preg_match($pattern, $source, $matches);

        if ($match === false) {
            $result  = '';
            $status  = 3;
            $message = $name . ($ck + 1) . '=regex_error:' . preg_last_error_msg();
        } elseif ($match === 1) {
            $result  = $matches[0];
            $status  = $this->onfailStatus($args);
            $message = $name . ($ck + 1) . '=' . ($args['errormessage'] ?? strlen($matches[0]));
        } else {
            $result  = '';
            $status  = 0;
            $message = $name . ($ck + 1) . '=0';
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['pattern' => $pattern, 'source' => $args['source'], 'result' => $result, 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_parsepattern(string $f, int $k, string $name, int $ck, array $args, $caseid, int $parsepatternid): array
    {
        $source  = $this->resolveSource($f, $k, $args['source']);
        $pattern = $args['pattern'];
        $result  = '';
        $errors  = 0;
        $match   = preg_match($pattern, $source, $matches);

        if ($match === false) {
            $status  = 3;
            $message = $name . ($ck + 1) . '=regex_error:' . preg_last_error_msg();
        } elseif ($match !== 1 || count($matches) < 2) {
            $status  = 3;
            $message = $name . ($ck + 1) . '=0';
        } else {
            $nbmatches = count($matches);
            for ($patternid = 1; $patternid < $nbmatches; $patternid++) {
                $val = $matches[$patternid];
                if ($val !== '') {
                    $this->Curly['parsepattern_results'][$f]['case'][$caseid][$parsepatternid][$patternid] = $val;
                    $result .= $val . ' ';
                } else {
                    $errors++;
                }
            }
            if ($errors === 0) {
                $status  = 0;
                $message = $name . ($ck + 1) . '=' . ($nbmatches - 1);
            } else {
                $status  = 3;
                $message = $name . ($ck + 1) . '=' . ($nbmatches - 1 - $errors);
            }
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['pattern' => $pattern, 'source' => $args['source'], 'result' => trim($result), 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    private function check_matchpatterncount(string $f, int $k, string $name, int $ck, array $args): array
    {
        $source     = $this->resolveSource($f, $k, $args['source']);
        $pattern    = $args['pattern'];
        $matchcount = (int)$args['matchcount'];
        $count      = preg_match_all($pattern, $source, $matches);

        if ($count === false) {
            $status  = 3;
            $message = $name . ($ck + 1) . '=regex_error:' . preg_last_error_msg();
            $result  = 0;
        } else {
            $result  = $count;
            $matched = ($count === $matchcount);
            $status  = $matched ? 0 : $this->onfailStatus($args);
            $message = $name . ($ck + 1) . '=' . ($matched ? $count : ($args['errormessage'] ?? $count));
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['pattern' => $pattern, 'source' => $args['source'], 'matchcount' => $matchcount, 'result' => $result, 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    /**
     * NEW: md5sum check
     * Computes MD5 of the curl response body and compares to expected hash.
     *
     * XML:
     *   <md5sum>
     *     <hash>d41d8cd98f00b204e9800998ecf8427e</hash>
     *     <onfail_status>CRITICAL</onfail_status>
     *   </md5sum>
     */
    private function check_md5sum(string $f, int $k, string $name, int $ck, array $args): array
    {
        $expected = strtolower($args['hash']);
        $body     = $this->Curly['result']['testcases'][$f][$k]['curl'];
        $result   = md5($body);

        if ($result === $expected) {
            $status  = 0;
            $message = $name . '=' . $result;
        } else {
            $status  = $this->onfailStatus($args);
            $message = $name . '=' . ($args['errormessage'] ?? 'got=' . $result . '_expected=' . $expected);
        }

        $this->storeCheckResult($f, $k, $name, $ck, ['hash' => $expected, 'result' => $result, 'message' => $message, 'status' => $status]);
        return [$status, $message];
    }

    // ─────────────────────────────────────────────
    //  JS / Chromium source
    // ─────────────────────────────────────────────

    /**
     * Resolve the content for a given source type.
     * 'chromium' renders the page with a headless Node.js script and returns the DOM HTML.
     *
     * The external script (curly-render.js) must:
     *   - Accept a URL as first argument
     *   - Print the rendered HTML to stdout
     *   - Exit 0 on success
     *
     * Minimal curly-render.js (Playwright):
     *
     *   const { chromium } = require('playwright');
     *   (async () => {
     *     const browser = await chromium.launch();
     *     const page    = await browser.newPage();
     *     await page.goto(process.argv[2], { waitUntil: 'networkidle' });
     *     console.log(await page.content());
     *     await browser.close();
     *   })();
     */
    private function resolveSource(string $f, int $k, string $source): string
    {
        if ($source === 'chromium') {
            return $this->fetchChromiumSource($f, $k);
        }
        return $this->Curly['result']['testcases'][$f][$k][$source] ?? '';
    }

    private function fetchChromiumSource(string $f, int $k): string
    {
        $tc = &$this->Curly['result']['testcases'][$f][$k];

        if (array_key_exists('chromium', $tc)) {
            return (string)$tc['chromium'];
        }

        $script = $this->Curly['conf']['chromium_script'];
        $url    = $tc['curl_setopt']['CURLOPT_URL'] ?? '';

        if (!is_file($script) || !is_readable($script)) {
            $message = 'chromium_script not found or not readable: ' . $script;
            $tc['chromium_error'] = $message;
            throw new \RuntimeException($message);
        }

        if (!is_string($url) || $url === '') {
            $message = 'chromium source requires CURLOPT_URL';
            $tc['chromium_error'] = $message;
            throw new \RuntimeException($message);
        }

        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            $message = 'chromium source only supports http/https URLs';
            $tc['chromium_error'] = $message;
            throw new \RuntimeException($message);
        }

        if (!function_exists('proc_open')) {
            $message = 'proc_open is unavailable; Chromium renderer cannot be started';
            $tc['chromium_error'] = $message;
            throw new \RuntimeException($message);
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open(['node', $script, $url], $descriptors, $pipes);
        if (!is_resource($process)) {
            $message = 'chromium render process could not be started';
            $tc['chromium_error'] = $message;
            throw new \RuntimeException($message);
        }

        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        if ($exitCode !== 0 || $output === false || trim($output) === '') {
            $detail = trim((string)$stderr);
            if ($detail !== '') {
                $detail = ': ' . substr(preg_replace('/\s+/', ' ', $detail), 0, 300);
            }
            $message = 'chromium render failed for ' . $this->redactUrl($url) . $detail;
            $tc['chromium_error'] = $message;
            throw new \RuntimeException($message);
        }

        // Cache the rendered DOM so several Chromium-backed checks do not re-render.
        $tc['chromium'] = $output;
        return $output;
    }

    // ─────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────

    private function onfailStatus(array $args, int $default = 2): int
    {
        if (isset($args['onfail_status'])) {
            return $this->Curly['conf']['exit_codes'][$args['onfail_status']];
        }
        return $default;
    }

    private function storeCheckResult(string $f, int $k, string $name, int $ck, array $data): void
    {
        $this->Curly['result']['testcases'][$f][$k]['checks'][$name][$ck] = $data;

        if ($this->Curly['conf']['debug']) {
            echo PHP_EOL . 'Check: ' . $name . PHP_EOL;
            print_r($this->redactSensitiveData($data));
            echo PHP_EOL;
        }
    }

    private function XmlToArray(\SimpleXMLElement $xml): array
    {
        try {
            $json = json_encode($xml, JSON_THROW_ON_ERROR);
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->bail('XML conversion failed: ' . $e->getMessage());
        }

        if (!is_array($data)) {
            $this->bail('XML conversion failed: expected an object/array structure');
        }

        return $data;
    }

    private function redactSensitiveData(mixed $value, ?string $key = null): mixed
    {
        $sensitiveKeys = [
            'CURLOPT_USERPWD',
            'CURLOPT_PROXYUSERPWD',
            'CURLOPT_USERNAME',
            'CURLOPT_PASSWORD',
            'CURLOPT_PROXYUSERNAME',
            'CURLOPT_PROXYPASSWORD',
            'CURLOPT_COOKIE',
            'CURLOPT_COOKIELIST',
            'CURLOPT_POSTFIELDS',
            'parsepattern_results',
        ];

        if ($key !== null && in_array($key, $sensitiveKeys, true)) {
            return '***REDACTED***';
        }

        if ($key === 'parsepattern' && is_array($value)) {
            foreach ($value as &$instance) {
                if (is_array($instance) && array_key_exists('result', $instance)) {
                    $instance['result'] = '***REDACTED***';
                }
            }
            unset($instance);
        }

        if (is_array($value)) {
            $redacted = [];
            foreach ($value as $childKey => $childValue) {
                if ($childKey === 'CURLOPT_HTTPHEADER') {
                    $redacted[$childKey] = $this->redactHeaders($childValue);
                    continue;
                }
                if (in_array((string)$childKey, ['url', 'redirect_url', 'CURLOPT_URL'], true) && is_string($childValue)) {
                    $redacted[$childKey] = $this->redactUrl($childValue);
                    continue;
                }
                $redacted[$childKey] = $this->redactSensitiveData($childValue, (string)$childKey);
            }
            return $redacted;
        }

        return $value;
    }

    private function redactHeaders(mixed $headers): mixed
    {
        if (is_array($headers)) {
            return array_map(fn($header) => $this->redactHeaders($header), $headers);
        }

        if (!is_string($headers)) {
            return $headers;
        }

        return preg_replace(
            '/(^|[|\\r\\n])(Authorization|Proxy-Authorization|Cookie|Set-Cookie)\\s*:[^|\\r\\n]*/i',
            '$1$2: ***REDACTED***',
            $headers
        );
    }

    private function redactUrl(string $url): string
    {
        $url = preg_replace(
            '#^(https?://)([^/@:\\s]+):([^@\\s]+)@#i',
            '$1$2:***REDACTED***@',
            $url
        );

        return preg_replace_callback(
            '/([?&](?:access_token|token|api[_-]?key|secret|password|passwd|signature|auth)=)[^&#]*/i',
            static fn(array $m): string => $m[1] . '***REDACTED***',
            $url
        );
    }

    private function sanitizeChecksForLog(array $checks): array
    {
        if (isset($checks['parsepattern']) && is_array($checks['parsepattern'])) {
            foreach ($checks['parsepattern'] as &$result) {
                if (is_array($result) && array_key_exists('result', $result)) {
                    $result['result'] = '***REDACTED***';
                }
            }
            unset($result);
        }

        return $this->redactSensitiveData($checks);
    }

    private function assertWritableDir(string $dir): void
    {
        if (!is_dir($dir)) {
            $this->bail('Directory not found: ' . $dir);
        }
        if (!is_writable($dir)) {
            $this->bail('Directory not writable: ' . $dir);
        }
    }

    /**
     * Print an UNKNOWN message and exit immediately.
     * $prefix allows injecting a custom prefix (e.g. testcase-specific).
     */
    private function bail(string $message, string $prefix = 'Curly UNKNOWN - '): never
    {
        echo $prefix . $message . PHP_EOL;
        exit($this->Curly['conf']['exit_codes']['UNKNOWN']);
    }

    // ─────────────────────────────────────────────
    //  End tasks: output, perfdatas, logging
    // ─────────────────────────────────────────────

    private function endtasks(): void
    {
        $this->deletecookies();
        $this->CurlyTime();

        $c = &$this->Curly['result']['counters'];
        $p = &$this->Curly['result']['output']['perfdatas'];

        $p .= 'Curlytime='    . $c['CurlyTime']      . ';0;0;0;0';
        $p .= ' casestime='   . $c['casestime']       . ';0;0;0;0';
        $p .= ' casesrun='    . $c['casesrun']         . ';0;0;0;0';
        $p .= ' casesok='     . $c['casesok']          . ';0;0;0;0';
        $p .= ' caseswarning='  . $c['caseswarning']   . ';0;0;0;0';
        $p .= ' casescritical=' . $c['casescritical']  . ';0;0;0;0';
        $p .= ' casesunknown='  . $c['casesunknown']   . ';0;0;0;0';
        $p .= ' checksrun='     . $c['checksrun']       . ';0;0;0;0';
        $p .= ' checksok='      . $c['checksok']        . ';0;0;0;0';
        $p .= ' checkswarning=' . $c['checkswarning']  . ';0;0;0;0';
        $p .= ' checkscritical=' . $c['checkscritical'] . ';0;0;0;0';
        $p .= ' checksunknown=' . $c['checksunknown']  . ';0;0;0;0';

        $o = &$this->Curly['result']['output'];

        if ($c['casesunknown'] !== 0) {
            $this->Curly['result']['exit_status'] = 3;
            $output = 'Curly UNKNOWN - '   . $o['UNKNOWN']  . ' |' . $p;
        } elseif ($c['casescritical'] !== 0) {
            $this->Curly['result']['exit_status'] = 2;
            $output = 'Curly CRITICAL - '  . $o['CRITICAL'] . ' |' . $p;
        } elseif ($c['caseswarning'] !== 0) {
            $this->Curly['result']['exit_status'] = 1;
            $output = 'Curly WARNING - '   . $o['WARNING']  . ' |' . $p;
        } else {
            $this->Curly['result']['exit_status'] = 0;
            $output = $this->Curly['conf']['output_ok_length'] === 'long'
                ? 'Curly OK - ' . $o['OK'] . ' |' . $p
                : 'Curly OK |'  . $p;
        }

        $o['stdout'] = preg_replace('/,?\s+/', ' ', $output);
        $this->LogResults();
    }

    private function deletecookies(): void
    {
        if (!$this->Curly['conf']['deletecookies']) {
            return;
        }
        foreach (['CURLOPT_COOKIEFILE', 'CURLOPT_COOKIEJAR'] as $key) {
            $path = $this->Curly['conf']['curl_setopt'][$key] ?? '';
            if ($path && is_file($path)) {
                @unlink($path);
            }
        }
    }

    private function CurlyTime(): void
    {
        $end = microtime(true);
        $this->Curly['result']['counters']['CurlyEndTime'] = $end;
        $this->Curly['result']['counters']['CurlyTime']    = round(
            $end - $this->Curly['result']['counters']['CurlyStartTime'],
            4
        );
    }

    /**
     * Append one JSON Lines entry per run to the log file.
     * Much easier to parse/grep than the old plaintext format.
     */
    private function LogResults(): void
    {
        if (!$this->Curly['conf']['logenable']) {
            return;
        }

        $logpath = $this->Curly['conf']['logsdir'] . '/' . $this->Curly['conf']['logfile'];
        $fh      = fopen($logpath, 'ab');

        if (!is_resource($fh)) {
            echo 'Curly UNKNOWN - ' . $logpath . ' fopen failed' . PHP_EOL;
            exit($this->Curly['conf']['exit_codes']['UNKNOWN']);
        }

        $entry = [
            'date'      => date('c'),
            'config'    => $this->xmlconfig,
            'status'    => $this->Curly['result']['exit_status'],
            'output'    => $this->Curly['result']['output']['stdout'],
            'counters'  => $this->Curly['result']['counters'],
            'testcases' => [],
        ];

        foreach ($this->Curly['result']['testcases'] as $file => $cases) {
            foreach ($cases as $casekey => $tc) {
                $entry['testcases'][] = [
                    'file'         => $file,
                    'caseid'       => $tc['caseid'],
                    'casename'     => $tc['casename'],
                    'curl_setopt'  => $this->redactSensitiveData($tc['curl_setopt']),
                    'curl_getinfo' => $this->redactSensitiveData($tc['curl_getinfo']),
                    'checks'       => $this->sanitizeChecksForLog($tc['checks']),
                    'is_ok'        => (int)(!$tc['is_warning'] && !$tc['is_critical'] && !$tc['is_unknown']),
                    'is_warning'   => $tc['is_warning'],
                    'is_critical'  => $tc['is_critical'],
                    'is_unknown'   => $tc['is_unknown'],
                    // Response body and verbose cURL trace are intentionally omitted.
                ];
            }
        }

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            echo 'Curly UNKNOWN - ' . $logpath . ' lock failed' . PHP_EOL;
            exit($this->Curly['conf']['exit_codes']['UNKNOWN']);
        }

        try {
            $line = json_encode(
                $entry,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
            ) . PHP_EOL;

            $written = fwrite($fh, $line);
            if ($written === false || $written !== strlen($line)) {
                throw new \RuntimeException('write failed or was incomplete');
            }

            fflush($fh);
        } catch (\Throwable $e) {
            flock($fh, LOCK_UN);
            fclose($fh);
            echo 'Curly UNKNOWN - ' . $logpath . ' logging failed: ' . $e->getMessage() . PHP_EOL;
            exit($this->Curly['conf']['exit_codes']['UNKNOWN']);
        }

        flock($fh, LOCK_UN);
        fclose($fh);
    }

}

$Curly = new Curly();
$Curly->CurlyExec($argv);
