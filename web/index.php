<?php
ini_set('display_errors', '1');
error_reporting(E_ALL);
set_time_limit(0);

$baseDir = '/app';
$pythonScript = $baseDir . '/phishing.py';
$defaultOutputRoot = $baseDir . '/checking_domains';
$wordlistsDir = $baseDir . '/wordlists';
$jobsDir = $defaultOutputRoot . '/_jobs';

if (!is_dir($jobsDir)) {
    @mkdir($jobsDir, 0775, true);
}

function h($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function normalizeRelativeWordlistPath(string $absolutePath): string {
    return './' . ltrim(str_replace('/app/', '', $absolutePath), '/');
}

function listWordlistFiles(string $wordlistsDir): array {
    $items = [];
    if (!is_dir($wordlistsDir)) {
        return $items;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($wordlistsDir, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $fileInfo) {
        if (!$fileInfo->isFile()) {
            continue;
        }
        $absolutePath = $fileInfo->getPathname();
        $relativePath = normalizeRelativeWordlistPath($absolutePath);
        $items[$relativePath] = [
            'absolute' => $absolutePath,
            'relative' => $relativePath,
            'name' => basename($absolutePath),
        ];
    }

    ksort($items, SORT_NATURAL | SORT_FLAG_CASE);
    return array_values($items);
}

function sanitizeChoice(string $value, array $allowed, string $default): string {
    return in_array($value, $allowed, true) ? $value : $default;
}

function sanitizeInt($value, int $default, int $min, int $max): int {
    $filtered = filter_var($value, FILTER_VALIDATE_INT);
    if ($filtered === false) {
        return $default;
    }
    return max($min, min($max, $filtered));
}

function sanitizeDomainDirectoryName(string $domain): string {
    $domain = strtolower(trim($domain));
    $domain = preg_replace('~^https?://~', '', $domain);
    $domain = preg_replace('~/.*$~', '', $domain);
    return $domain;
}

function loadTranslations(string $baseDir): array {
    $candidates = [
        $baseDir . '/web/lang.php',
        __DIR__ . '/lang.php',
    ];

    foreach ($candidates as $file) {
        if (is_file($file)) {
            $translations = require $file;
            return is_array($translations) ? $translations : [];
        }
    }

    return [];
}

function trValue(array $translations, string $lang, string $key, array $vars = []) {
    $value = $translations[$lang][$key] ?? $translations['en'][$key] ?? $key;
    if (is_array($value)) {
        return $value;
    }
    $value = (string)$value;
    foreach ($vars as $name => $replacement) {
        $value = str_replace('{' . $name . '}', (string)$replacement, $value);
    }
    return $value;
}

function statusLabel(?string $status, array $translations, string $lang): string {
    $map = [
        'False positive' => 'status_false_positive',
        'True positive' => 'status_true_positive',
        'Selling' => 'status_selling',
        'Unchecked' => 'status_unchecked',
        'NO_DNS' => 'status_no_dns',
        '' => 'status_empty',
        null => 'status_empty',
    ];
    $key = $map[$status] ?? null;
    return $key ? (string)trValue($translations, $lang, $key) : (string)$status;
}

$translations = loadTranslations($baseDir);
if (!$translations) {
    $translations = ['en' => []];
}
$langOptions = array_keys($translations);
$lang = strtolower((string)($_GET['lang'] ?? $_COOKIE['phishing_domains_lang'] ?? 'en'));
$lang = sanitizeChoice($lang, $langOptions, 'en');
if (isset($_GET['lang'])) {
    @setcookie('phishing_domains_lang', $lang, time() + 60 * 60 * 24 * 365, '/');
}
$t = static fn(string $key, array $vars = []) => trValue($translations, $lang, $key, $vars);
$tooltips = trValue($translations, $lang, 'tooltips');
if (!is_array($tooltips)) {
    $tooltips = [];
}
$manualStatuses = [
    'False positive' => (string)$t('status_false_positive'),
    'True positive' => (string)$t('status_true_positive'),
    'Selling' => (string)$t('status_selling'),
];

function buildCommandParts(array $form, string $pythonScript): array {
    $command = [
        'python3',
        $pythonScript,
        '--tlds', $form['tlds'],
        '--keywords', $form['keywords'],
        '--mode', $form['mode'],
        '--keyword-target', $form['keyword_target'],
        '--format', $form['format'],
        '--host-workers', (string)$form['host_workers'],
        '--host-timeout', (string)$form['host_timeout'],
        '--screenshot-workers', (string)$form['screenshot_workers'],
        '--http-timeout', (string)$form['http_timeout'],
        '--browser-timeout', (string)$form['browser_timeout'],
    ];

    if ($form['unicode']) {
        $command[] = '--unicode';
    }
    if ($form['labels_only']) {
        $command[] = '--labels-only';
    }
    if ($form['show_stats']) {
        $command[] = '--show-stats';
    }

    $command[] = $form['domain'];
    return $command;
}

function launchBackgroundJob(array $commandParts, array $form, string $jobsDir, string $baseDir, string $message): array {
    if (!is_dir($jobsDir)) {
        @mkdir($jobsDir, 0775, true);
    }

    $jobId = date('Ymd_His') . '_' . bin2hex(random_bytes(4));
    $logPath = $jobsDir . '/' . $jobId . '.log';
    $exitPath = $jobsDir . '/' . $jobId . '.exit';
    $donePath = $jobsDir . '/' . $jobId . '.done';
    $metaPath = $jobsDir . '/' . $jobId . '.json';

    $shellCommand = implode(' ', array_map('escapeshellarg', $commandParts));
    $inner = 'export HOME=/tmp'
        . ' XDG_CACHE_HOME=/tmp/.cache'
        . ' XDG_CONFIG_HOME=/tmp/.config'
        . ' XDG_RUNTIME_DIR=/tmp/runtime-www-data'
        . ' TMPDIR=/tmp'
        . ' PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        . '; mkdir -p /tmp/.cache /tmp/.config /tmp/runtime-www-data /tmp/chrome-profile && chmod 700 /tmp/runtime-www-data'
        . '; cd ' . escapeshellarg($baseDir)
        . ' && ' . $shellCommand
        . ' > ' . escapeshellarg($logPath) . ' 2>&1'
        . '; code=$?'
        . '; printf "%s" "$code" > ' . escapeshellarg($exitPath)
        . '; date +%Y-%m-%d\ %H:%M:%S > ' . escapeshellarg($donePath);

    $launcher = 'nohup bash -lc ' . escapeshellarg($inner) . ' >/dev/null 2>&1 & echo $!';
    $pid = trim((string)shell_exec($launcher));

    if ($pid === '' || !ctype_digit($pid)) {
        return [
            'ok' => false,
            'message' => $message,
        ];
    }

    $meta = [
        'job_id' => $jobId,
        'pid' => (int)$pid,
        'created_at' => date('Y-m-d H:i:s'),
        'domain' => $form['domain'],
        'domain_dir' => sanitizeDomainDirectoryName($form['domain']),
        'command' => $commandParts,
        'log_file' => basename($logPath),
        'exit_file' => basename($exitPath),
        'done_file' => basename($donePath),
    ];

    file_put_contents($metaPath, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

    return [
        'ok' => true,
        'message' => $message,
        'job_id' => $jobId,
        'pid' => (int)$pid,
        'meta' => $meta,
    ];
}

function isProcessRunning(int $pid): bool {
    if ($pid <= 0) {
        return false;
    }
    return file_exists('/proc/' . $pid);
}

function listJobs(string $jobsDir): array {
    $items = [];
    if (!is_dir($jobsDir)) {
        return $items;
    }

    foreach (glob($jobsDir . '/*.json') ?: [] as $metaFile) {
        $meta = json_decode((string)@file_get_contents($metaFile), true);
        if (!is_array($meta)) {
            continue;
        }

        $jobId = $meta['job_id'] ?? basename($metaFile, '.json');
        $logPath = $jobsDir . '/' . ($meta['log_file'] ?? ($jobId . '.log'));
        $exitPath = $jobsDir . '/' . ($meta['exit_file'] ?? ($jobId . '.exit'));
        $donePath = $jobsDir . '/' . ($meta['done_file'] ?? ($jobId . '.done'));
        $pid = (int)($meta['pid'] ?? 0);

        $exitCode = is_file($exitPath) ? trim((string)@file_get_contents($exitPath)) : null;
        $doneAt = is_file($donePath) ? trim((string)@file_get_contents($donePath)) : null;

        if ($exitCode !== null && $exitCode !== '') {
            $status = ((int)$exitCode === 0) ? 'finished_ok' : 'finished_error';
        } elseif (isProcessRunning($pid)) {
            $status = 'running';
        } else {
            $status = 'unknown';
        }

        $items[] = [
            'job_id' => $jobId,
            'pid' => $pid,
            'domain' => $meta['domain'] ?? '—',
            'created_at' => $meta['created_at'] ?? '',
            'domain_dir' => $meta['domain_dir'] ?? '',
            'status' => $status,
            'exit_code' => $exitCode,
            'done_at' => $doneAt,
            'log_file' => is_file($logPath) ? basename($logPath) : null,
            'log_size' => is_file($logPath) ? (@filesize($logPath) ?: 0) : 0,
        ];
    }

    usort($items, static function ($a, $b) {
        return strcmp((string)$b['created_at'], (string)$a['created_at']);
    });

    return $items;
}

function getLatestJobMap(array $jobs): array {
    $map = [];
    foreach ($jobs as $job) {
        $domain = sanitizeDomainDirectoryName((string)($job['domain'] ?? $job['domain_dir'] ?? ''));
        if ($domain === '') {
            continue;
        }
        if (!isset($map[$domain])) {
            $map[$domain] = $job;
        }
    }
    return $map;
}

function listRecentRuns(string $outputRoot): array {
    $items = [];
    if (!is_dir($outputRoot)) {
        return $items;
    }

    foreach (scandir($outputRoot) as $entry) {
        if ($entry === '.' || $entry === '..' || $entry === '_jobs') {
            continue;
        }

        $domainDir = $outputRoot . DIRECTORY_SEPARATOR . $entry;
        if (!is_dir($domainDir)) {
            continue;
        }

        $latestOutput = null;
        $latestMtime = 0;
        foreach (glob($domainDir . '/output_*') ?: [] as $outputFile) {
            $mtime = @filemtime($outputFile) ?: 0;
            if ($mtime >= $latestMtime) {
                $latestMtime = $mtime;
                $latestOutput = $outputFile;
            }
        }

        $sqliteFile = $domainDir . '/' . $entry . '.sqlite3';
        $screenshotsDir = $domainDir . '/screenshots';
        $screenshotCount = 0;
        if (is_dir($screenshotsDir)) {
            $screenshotCount = count(glob($screenshotsDir . '/*.png') ?: []);
        }

        $items[] = [
            'domain' => $entry,
            'domain_dir' => $domainDir,
            'latest_output' => $latestOutput,
            'sqlite' => is_file($sqliteFile) ? $sqliteFile : null,
            'screenshot_count' => $screenshotCount,
            'mtime' => max($latestMtime, @filemtime($sqliteFile) ?: 0),
        ];
    }

    usort($items, fn($a, $b) => $b['mtime'] <=> $a['mtime']);
    return $items;
}

function getDomainDbPath(string $outputRoot, string $domain): ?string {
    $clean = sanitizeDomainDirectoryName($domain);
    if ($clean === '') {
        return null;
    }
    $dbPath = $outputRoot . '/' . $clean . '/' . $clean . '.sqlite3';
    return is_file($dbPath) ? $dbPath : null;
}

function openSqlitePdo(string $dbPath): PDO {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
}

function appendLogEntryPhp(?string $existingLog, string $message): string {
    $eventTime = date('Y-m-d H:i:s');
    $entry = '[' . $eventTime . '] ' . $message;
    if ($existingLog !== null && trim($existingLog) !== '') {
        return rtrim($existingLog) . "\n" . $entry;
    }
    return $entry;
}

function updateDomainStatusInDb(string $dbPath, string $checkingDomain, string $newStatus, array $messages): array {
    $pdo = openSqlitePdo($dbPath);
    $stmt = $pdo->prepare('SELECT "Status", "Log" FROM domains WHERE "Checking domain" = :domain');
    $stmt->execute([':domain' => $checkingDomain]);
    $row = $stmt->fetch();

    if (!$row) {
        return ['ok' => false, 'message' => $messages['not_found']];
    }

    $oldStatus = $row['Status'] ?? null;
    $log = $row['Log'] ?? null;
    if ($oldStatus === $newStatus) {
        return ['ok' => true, 'message' => $messages['already_set'], 'status' => $newStatus];
    }

    $newLog = appendLogEntryPhp($log, 'Manual review status changed: ' . ($oldStatus ?: 'NULL') . ' -> ' . $newStatus . '.');
    $update = $pdo->prepare('UPDATE domains SET "Status" = :status, "Log" = :log WHERE "Checking domain" = :domain');
    $update->execute([
        ':status' => $newStatus,
        ':log' => $newLog,
        ':domain' => $checkingDomain,
    ]);

    return ['ok' => true, 'message' => $messages['updated'], 'status' => $newStatus];
}

function getDomainSummaryStats(string $dbPath): array {
    $pdo = openSqlitePdo($dbPath);
    $sql = 'SELECT '
        . 'MIN("First Check Date") AS first_check, '
        . 'MAX("Last check date") AS last_check, '
        . 'COUNT(*) AS generated_total, '
        . 'SUM(CASE WHEN "IP address" IS NOT NULL AND TRIM("IP address") <> "" THEN 1 ELSE 0 END) AS live_total, '
        . 'SUM(CASE WHEN "Screenshot" IS NOT NULL AND TRIM("Screenshot") <> "" THEN 1 ELSE 0 END) AS screenshot_total, '
        . 'SUM(CASE WHEN "Status" = "True positive" THEN 1 ELSE 0 END) AS true_positive_total, '
        . 'SUM(CASE WHEN "Status" = "False positive" THEN 1 ELSE 0 END) AS false_positive_total, '
        . 'SUM(CASE WHEN "Status" = "Selling" THEN 1 ELSE 0 END) AS selling_total, '
        . 'SUM(CASE WHEN "Status" = "Unchecked" THEN 1 ELSE 0 END) AS unchecked_total, '
        . 'SUM(CASE WHEN "Status" = "NO_DNS" THEN 1 ELSE 0 END) AS no_dns_total '
        . 'FROM domains';
    $row = $pdo->query($sql)->fetch();
    return $row ?: [];
}

function enrichRunsWithDbStats(array $runs, array $latestJobMap, array $labels): array {
    foreach ($runs as &$run) {
        $run['first_check'] = null;
        $run['last_check'] = null;
        $run['generated_total'] = null;
        $run['live_total'] = null;
        $run['status_label'] = $run['sqlite'] ? $labels['done'] : $labels['empty'];
        $run['status_class'] = 'muted';
        $run['status_log'] = null;

        $job = $latestJobMap[$run['domain']] ?? null;
        if ($job) {
            $run['status_log'] = $job['log_file'];
            if (($job['status'] ?? '') === 'running') {
                $run['status_label'] = $labels['running'];
                $run['status_class'] = 'running';
            } elseif (($job['status'] ?? '') === 'finished_error') {
                $run['status_label'] = $labels['error'];
                $run['status_class'] = 'fail';
            } else {
                $run['status_label'] = $labels['done'];
                $run['status_class'] = 'ok';
            }
        }

        if ($run['sqlite']) {
            try {
                $stats = getDomainSummaryStats($run['sqlite']);
                $run['first_check'] = $stats['first_check'] ?? null;
                $run['last_check'] = $stats['last_check'] ?? null;
                $run['generated_total'] = isset($stats['generated_total']) ? (int)$stats['generated_total'] : 0;
                $run['live_total'] = isset($stats['live_total']) ? (int)$stats['live_total'] : 0;
                $run['screenshot_count'] = isset($stats['screenshot_total']) ? (int)$stats['screenshot_total'] : (int)$run['screenshot_count'];
            } catch (Throwable $e) {
                $run['status_label'] = $labels['db_error'];
                $run['status_class'] = 'fail';
            }
        }
    }
    unset($run);
    return $runs;
}

function getPaginatedDomainEntries(string $dbPath, int $page, int $perPage): array {
    $pdo = openSqlitePdo($dbPath);
    $countSql = 'SELECT COUNT(*) FROM domains WHERE "Screenshot" IS NOT NULL AND TRIM("Screenshot") <> ""';
    $total = (int)$pdo->query($countSql)->fetchColumn();

    $pageCount = max(1, (int)ceil($total / max(1, $perPage)));
    $page = max(1, min($page, $pageCount));
    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        'SELECT "Checking domain", "First Check Date", "First live appear date", "Last check date", "IP address", "Screenshot", "Final URL", "HTTP Status Code", "Status", "Log" '
        . 'FROM domains '
        . 'WHERE "Screenshot" IS NOT NULL AND TRIM("Screenshot") <> "" '
        . 'ORDER BY COALESCE("Last check date", "First Check Date") DESC, "Checking domain" ASC '
        . 'LIMIT :limit OFFSET :offset'
    );
    $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();

    return [
        'total' => $total,
        'page' => $page,
        'per_page' => $perPage,
        'page_count' => $pageCount,
        'rows' => $rows,
    ];
}

function getReportScreenshotRows(string $dbPath, string $status): array {
    $pdo = openSqlitePdo($dbPath);
    $stmt = $pdo->prepare(
        'SELECT "Checking domain", "First Check Date", "First live appear date", "Last check date", "IP address", "Screenshot", "Final URL", "HTTP Status Code", "Status" '
        . 'FROM domains '
        . 'WHERE "Status" = :status AND "Screenshot" IS NOT NULL AND TRIM("Screenshot") <> "" '
        . 'ORDER BY "Checking domain" ASC'
    );
    $stmt->execute([':status' => $status]);
    return $stmt->fetchAll();
}

function getReportGeneratedRows(string $dbPath): array {
    $pdo = openSqlitePdo($dbPath);
    $stmt = $pdo->query(
        'SELECT "Checking domain", "Status", "IP address", "Last check date" '
        . 'FROM domains '
        . 'WHERE COALESCE("Status", "") <> "False positive" '
        . 'ORDER BY "Checking domain" ASC'
    );
    return $stmt->fetchAll();
}

function buildPageUrl(array $params = []): string {
    $merged = array_merge($_GET, $params);
    foreach ($merged as $key => $value) {
        if ($value === null || $value === '') {
            unset($merged[$key]);
        }
    }
    return '/?' . http_build_query($merged);
}

function normalizeScreenshotBase64(?string $value): string {
    return preg_replace('/\s+/', '', (string)$value);
}

function renderReportDomainCards(array $rows, array $translations, string $lang): string {
    if (!$rows) {
        return '<p class="muted">' . h(trValue($translations, $lang, 'report_no_rows')) . '</p>';
    }

    $html = '';
    foreach ($rows as $row) {
        $screenshot = normalizeScreenshotBase64($row['Screenshot'] ?? '');
        if ($screenshot === '') {
            continue;
        }
        $html .= '<article class="shot-card">';
        $html .= '<h3>' . h($row['Checking domain'] ?? '') . '</h3>';
        $html .= '<div class="meta-grid">';
        if (!empty($row['_monitored_domain'])) {
            $html .= '<div><b>' . h(trValue($translations, $lang, 'report_source_domain')) . ':</b> ' . h($row['_monitored_domain']) . '</div>';
        }
        $html .= '<div><b>' . h(trValue($translations, $lang, 'status')) . ':</b> ' . h(statusLabel($row['Status'] ?? null, $translations, $lang)) . '</div>'
            . '<div><b>' . h(trValue($translations, $lang, 'ip')) . ':</b> ' . h(($row['IP address'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</div>'
            . '<div><b>' . h(trValue($translations, $lang, 'http')) . ':</b> ' . h(($row['HTTP Status Code'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</div>'
            . '<div><b>' . h(trValue($translations, $lang, 'last_check')) . ':</b> ' . h(($row['Last check date'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</div>'
            . '</div>';
        if (!empty($row['Final URL'])) {
            $html .= '<div class="url"><b>' . h(trValue($translations, $lang, 'final_url')) . ':</b> ' . h($row['Final URL']) . '</div>';
        }
        $html .= '<img class="screenshot" src="data:image/png;base64,' . h($screenshot) . '" alt="' . h($row['Checking domain'] ?? '') . '">';
        $html .= '</article>';
    }
    return $html ?: '<p class="muted">' . h(trValue($translations, $lang, 'report_no_rows')) . '</p>';
}

function renderReportHtml(string $domain, array $stats, array $truePositiveRows, array $sellingRows, array $generatedRows, array $translations, string $lang): string {
    $summary = [
        trValue($translations, $lang, 'checked_domain') => $domain,
        trValue($translations, $lang, 'first_check') => $stats['first_check'] ?? trValue($translations, $lang, 'not_available'),
        trValue($translations, $lang, 'last_check') => $stats['last_check'] ?? trValue($translations, $lang, 'not_available'),
        trValue($translations, $lang, 'generated') => (int)($stats['generated_total'] ?? 0),
        trValue($translations, $lang, 'live') => (int)($stats['live_total'] ?? 0),
        trValue($translations, $lang, 'screenshots') => (int)($stats['screenshot_total'] ?? 0),
        trValue($translations, $lang, 'true_positive') => (int)($stats['true_positive_total'] ?? 0),
        trValue($translations, $lang, 'selling') => (int)($stats['selling_total'] ?? 0),
        trValue($translations, $lang, 'unchecked') => (int)($stats['unchecked_total'] ?? 0),
        trValue($translations, $lang, 'no_dns') => (int)($stats['no_dns_total'] ?? 0),
    ];

    $summaryHtml = '';
    foreach ($summary as $label => $value) {
        $summaryHtml .= '<div class="summary-item"><strong>' . h($label) . '</strong><span>' . h($value) . '</span></div>';
    }

    $generatedHtml = '';
    foreach ($generatedRows as $row) {
        $domainCell = h($row['Checking domain'] ?? '');
        if (!empty($row['_monitored_domain'])) {
            $domainCell .= '<div class="cell-muted">' . h(trValue($translations, $lang, 'report_source_domain')) . ': ' . h($row['_monitored_domain']) . '</div>';
        }
        $generatedHtml .= '<tr>'
            . '<td>' . $domainCell . '</td>'
            . '<td>' . h(statusLabel($row['Status'] ?? null, $translations, $lang)) . '</td>'
            . '<td>' . h(($row['IP address'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h(($row['Last check date'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</td>'
            . '</tr>';
    }

    $css = <<<'CSS'
        @page { size: A4; margin: 14mm; }
        * { box-sizing: border-box; }
        body { font-family: Arial, Helvetica, sans-serif; margin: 0; color: #111827; background: #ffffff; font-size: 12px; line-height: 1.45; }
        h1 { margin: 0 0 8px; font-size: 28px; }
        h2 { margin: 28px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #d1d5db; font-size: 20px; }
        h3 { margin: 0 0 8px; font-size: 16px; word-break: break-all; }
        .muted { color: #6b7280; }
        .cell-muted { color: #6b7280; font-size: 9px; margin-top: 2px; }
        .cover { margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin: 16px 0 10px; }
        .summary-item { border: 1px solid #d1d5db; border-radius: 8px; padding: 8px; min-height: 58px; }
        .summary-item strong { display: block; color: #6b7280; font-size: 10px; text-transform: uppercase; margin-bottom: 4px; }
        .summary-item span { font-size: 14px; font-weight: 700; word-break: break-word; }
        .shot-card { page-break-inside: avoid; break-inside: avoid; border: 1px solid #d1d5db; border-radius: 10px; padding: 12px; margin: 0 0 14px; }
        .meta-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 4px 12px; margin: 8px 0; color: #374151; }
        .url { margin: 8px 0; word-break: break-all; color: #374151; }
        .screenshot { display: block; width: 100%; max-height: 420px; object-fit: contain; border: 1px solid #e5e7eb; border-radius: 6px; background: #f9fafb; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; font-size: 10px; }
        thead { display: table-header-group; }
        tr { page-break-inside: avoid; break-inside: avoid; }
        th, td { text-align: left; vertical-align: top; padding: 6px 5px; border-bottom: 1px solid #e5e7eb; word-break: break-word; }
        th { background: #f3f4f6; color: #374151; }
CSS;

    return '<!doctype html><html lang="' . h(trValue($translations, $lang, 'html_lang')) . '"><head><meta charset="utf-8"><title>' . h(trValue($translations, $lang, 'report_title')) . '</title><style>' . $css . '</style></head><body>'
        . '<section class="cover"><h1>' . h(trValue($translations, $lang, 'report_title')) . '</h1>'
        . '<div class="muted">' . h(trValue($translations, $lang, 'report_generated_at')) . ': ' . h(date('Y-m-d H:i:s')) . '</div>'
        . '<h2>' . h(trValue($translations, $lang, 'report_summary')) . '</h2>'
        . '<div class="summary-grid">' . $summaryHtml . '</div></section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_true_positive_section')) . '</h2>'
        . renderReportDomainCards($truePositiveRows, $translations, $lang) . '</section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_selling_section')) . '</h2>'
        . renderReportDomainCards($sellingRows, $translations, $lang) . '</section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_generated_table_title')) . '</h2>'
        . '<p class="muted">' . h(trValue($translations, $lang, 'report_generated_table_note')) . '</p>'
        . '<table><thead><tr><th>' . h(trValue($translations, $lang, 'report_domain_column')) . '</th><th>' . h(trValue($translations, $lang, 'report_status_column')) . '</th><th>' . h(trValue($translations, $lang, 'report_ip_column')) . '</th><th>' . h(trValue($translations, $lang, 'report_last_check_column')) . '</th></tr></thead><tbody>' . $generatedHtml . '</tbody></table></section>'
        . '</body></html>';
}

function streamPdfFromHtml(string $html, string $filenameBase): void {
    $safeName = preg_replace('~[^a-z0-9._-]+~i', '-', $filenameBase) ?: 'phishing-report';
    $htmlPath = tempnam(sys_get_temp_dir(), 'phishing_report_') . '.html';
    $pdfPath = tempnam(sys_get_temp_dir(), 'phishing_report_') . '.pdf';
    $profileDir = sys_get_temp_dir() . '/chrome-report-' . bin2hex(random_bytes(6));
    file_put_contents($htmlPath, $html);
    @mkdir($profileDir, 0700, true);

    $chrome = trim((string)shell_exec('command -v chromium || command -v chromium-browser || command -v google-chrome || true'));
    if ($chrome === '') {
        @unlink($htmlPath);
        @shell_exec('rm -rf ' . escapeshellarg($profileDir));
        throw new RuntimeException('Chromium executable was not found.');
    }

    $env = 'HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_CONFIG_HOME=/tmp/.config XDG_RUNTIME_DIR=/tmp/runtime-www-data TMPDIR=/tmp';
    $command = 'timeout 120s env ' . $env . ' ' . escapeshellarg($chrome)
        . ' --headless --no-sandbox --disable-gpu --disable-dev-shm-usage'
        . ' --disable-extensions --disable-background-networking --disable-sync'
        . ' --run-all-compositor-stages-before-draw --virtual-time-budget=10000'
        . ' --user-data-dir=' . escapeshellarg($profileDir)
        . ' --print-to-pdf=' . escapeshellarg($pdfPath)
        . ' ' . escapeshellarg('file://' . $htmlPath)
        . ' 2>&1';
    exec($command, $output, $code);

    if ($code !== 0 || !is_file($pdfPath) || filesize($pdfPath) === 0) {
        @unlink($htmlPath);
        @unlink($pdfPath);
        @shell_exec('rm -rf ' . escapeshellarg($profileDir));
        throw new RuntimeException(trim(implode("\n", $output)) ?: 'Chromium failed to generate PDF.');
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . $safeName . '-' . date('Ymd-His') . '.pdf"');
    header('Content-Length: ' . filesize($pdfPath));
    header('Cache-Control: private, max-age=0, must-revalidate');
    readfile($pdfPath);
    @unlink($htmlPath);
    @unlink($pdfPath);
    @shell_exec('rm -rf ' . escapeshellarg($profileDir));
    exit;
}

function exportReportPdf(string $domain, string $dbPath, array $translations, string $lang): void {
    $stats = getDomainSummaryStats($dbPath);
    $truePositiveRows = getReportScreenshotRows($dbPath, 'True positive');
    $sellingRows = getReportScreenshotRows($dbPath, 'Selling');
    $generatedRows = getReportGeneratedRows($dbPath);
    $html = renderReportHtml($domain, $stats, $truePositiveRows, $sellingRows, $generatedRows, $translations, $lang);

    streamPdfFromHtml($html, 'phishing-report-' . $domain);
}

function appendMonitoredDomainToRows(array $rows, string $monitoredDomain): array {
    foreach ($rows as &$row) {
        $row['_monitored_domain'] = $monitoredDomain;
    }
    unset($row);
    return $rows;
}

function collectAllReportData(array $runs): array {
    $dashboardRows = [];
    $truePositiveRows = [];
    $sellingRows = [];
    $generatedRows = [];

    foreach ($runs as $run) {
        $dashboardRows[] = $run;

        if (empty($run['sqlite']) || !is_file((string)$run['sqlite'])) {
            continue;
        }

        $domain = (string)($run['domain'] ?? '');
        $truePositiveRows = array_merge($truePositiveRows, appendMonitoredDomainToRows(getReportScreenshotRows((string)$run['sqlite'], 'True positive'), $domain));
        $sellingRows = array_merge($sellingRows, appendMonitoredDomainToRows(getReportScreenshotRows((string)$run['sqlite'], 'Selling'), $domain));
        $generatedRows = array_merge($generatedRows, appendMonitoredDomainToRows(getReportGeneratedRows((string)$run['sqlite']), $domain));
    }

    return [
        'dashboard_rows' => $dashboardRows,
        'true_positive_rows' => $truePositiveRows,
        'selling_rows' => $sellingRows,
        'generated_rows' => $generatedRows,
    ];
}

function renderAllReportsHtml(array $runs, array $translations, string $lang): string {
    $data = collectAllReportData($runs);

    $dashboardHtml = '';
    foreach ($data['dashboard_rows'] as $run) {
        $dashboardHtml .= '<tr>'
            . '<td>' . h($run['domain'] ?? '') . '</td>'
            . '<td>' . h($run['status_label'] ?? trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h(($run['first_check'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h(($run['last_check'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h($run['generated_total'] ?? trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h($run['live_total'] ?? trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h($run['screenshot_count'] ?? 0) . '</td>'
            . '<td>' . h(!empty($run['mtime']) ? date('Y-m-d H:i:s', (int)$run['mtime']) : trValue($translations, $lang, 'not_available')) . '</td>'
            . '</tr>';
    }
    if ($dashboardHtml === '') {
        $dashboardHtml = '<tr><td colspan="8">' . h(trValue($translations, $lang, 'report_no_rows')) . '</td></tr>';
    }

    $generatedHtml = '';
    foreach ($data['generated_rows'] as $row) {
        $domainCell = h($row['Checking domain'] ?? '');
        if (!empty($row['_monitored_domain'])) {
            $domainCell .= '<div class="cell-muted">' . h(trValue($translations, $lang, 'report_source_domain')) . ': ' . h($row['_monitored_domain']) . '</div>';
        }
        $generatedHtml .= '<tr>'
            . '<td>' . $domainCell . '</td>'
            . '<td>' . h(statusLabel($row['Status'] ?? null, $translations, $lang)) . '</td>'
            . '<td>' . h(($row['IP address'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</td>'
            . '<td>' . h(($row['Last check date'] ?? '') ?: trValue($translations, $lang, 'not_available')) . '</td>'
            . '</tr>';
    }
    if ($generatedHtml === '') {
        $generatedHtml = '<tr><td colspan="4">' . h(trValue($translations, $lang, 'report_no_rows')) . '</td></tr>';
    }

    $css = <<<'CSS'
        @page { size: A4; margin: 14mm; }
        * { box-sizing: border-box; }
        body { font-family: Arial, Helvetica, sans-serif; margin: 0; color: #111827; background: #ffffff; font-size: 12px; line-height: 1.45; }
        h1 { margin: 0 0 8px; font-size: 28px; }
        h2 { margin: 28px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #d1d5db; font-size: 20px; }
        h3 { margin: 0 0 8px; font-size: 16px; word-break: break-all; }
        .muted { color: #6b7280; }
        .cell-muted { color: #6b7280; font-size: 9px; margin-top: 2px; }
        .cover { margin-bottom: 20px; }
        .shot-card { page-break-inside: avoid; break-inside: avoid; border: 1px solid #d1d5db; border-radius: 10px; padding: 12px; margin: 0 0 14px; }
        .meta-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 4px 12px; margin: 8px 0; color: #374151; }
        .url { margin: 8px 0; word-break: break-all; color: #374151; }
        .screenshot { display: block; width: 100%; max-height: 420px; object-fit: contain; border: 1px solid #e5e7eb; border-radius: 6px; background: #f9fafb; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; font-size: 10px; }
        thead { display: table-header-group; }
        tr { page-break-inside: avoid; break-inside: avoid; }
        th, td { text-align: left; vertical-align: top; padding: 6px 5px; border-bottom: 1px solid #e5e7eb; word-break: break-word; }
        th { background: #f3f4f6; color: #374151; }
CSS;

    return '<!doctype html><html lang="' . h(trValue($translations, $lang, 'html_lang')) . '"><head><meta charset="utf-8"><title>' . h(trValue($translations, $lang, 'report_all_title')) . '</title><style>' . $css . '</style></head><body>'
        . '<section class="cover"><h1>' . h(trValue($translations, $lang, 'report_all_title')) . '</h1>'
        . '<div class="muted">' . h(trValue($translations, $lang, 'report_generated_at')) . ': ' . h(date('Y-m-d H:i:s')) . '</div></section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_dashboard_section')) . '</h2>'
        . '<table><thead><tr><th>' . h(trValue($translations, $lang, 'checked_domain')) . '</th><th>' . h(trValue($translations, $lang, 'status')) . '</th><th>' . h(trValue($translations, $lang, 'first_check')) . '</th><th>' . h(trValue($translations, $lang, 'last_check')) . '</th><th>' . h(trValue($translations, $lang, 'generated')) . '</th><th>' . h(trValue($translations, $lang, 'live')) . '</th><th>' . h(trValue($translations, $lang, 'screenshots')) . '</th><th>' . h(trValue($translations, $lang, 'updated')) . '</th></tr></thead><tbody>' . $dashboardHtml . '</tbody></table></section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_true_positive_section')) . '</h2>'
        . renderReportDomainCards($data['true_positive_rows'], $translations, $lang) . '</section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_selling_section')) . '</h2>'
        . renderReportDomainCards($data['selling_rows'], $translations, $lang) . '</section>'
        . '<section><h2>' . h(trValue($translations, $lang, 'report_generated_table_title')) . '</h2>'
        . '<p class="muted">' . h(trValue($translations, $lang, 'report_generated_table_note')) . '</p>'
        . '<table><thead><tr><th>' . h(trValue($translations, $lang, 'report_domain_column')) . '</th><th>' . h(trValue($translations, $lang, 'report_status_column')) . '</th><th>' . h(trValue($translations, $lang, 'report_ip_column')) . '</th><th>' . h(trValue($translations, $lang, 'report_last_check_column')) . '</th></tr></thead><tbody>' . $generatedHtml . '</tbody></table></section>'
        . '</body></html>';
}

function exportAllReportsPdf(array $runs, array $translations, string $lang): void {
    $html = renderAllReportsHtml($runs, $translations, $lang);
    streamPdfFromHtml($html, 'phishing-dashboard-report');
}

$wordlistFiles = listWordlistFiles($wordlistsDir);
$wordlistOptions = array_map(static fn($item) => $item['relative'], $wordlistFiles);
$defaultTld = in_array('./wordlists/tlds.txt', $wordlistOptions, true) ? './wordlists/tlds.txt' : ($wordlistOptions[0] ?? '');
$defaultKeywords = in_array('./wordlists/suffix.txt', $wordlistOptions, true) ? './wordlists/suffix.txt' : ($wordlistOptions[0] ?? '');

$modeOptions = ['mutations', 'keywords', 'all'];
$keywordTargetOptions = ['base', 'mutations', 'both'];
$formatOptions = ['txt', 'json'];
$tabOptions = ['dashboard', 'scan'];

$form = [
    'domain' => trim((string)($_POST['domain'] ?? '')),
    'tlds' => sanitizeChoice((string)($_POST['tlds'] ?? $defaultTld), $wordlistOptions, $defaultTld),
    'keywords' => sanitizeChoice((string)($_POST['keywords'] ?? $defaultKeywords), $wordlistOptions, $defaultKeywords),
    'mode' => sanitizeChoice((string)($_POST['mode'] ?? 'all'), $modeOptions, 'all'),
    'keyword_target' => sanitizeChoice((string)($_POST['keyword_target'] ?? 'base'), $keywordTargetOptions, 'base'),
    'format' => sanitizeChoice((string)($_POST['format'] ?? 'txt'), $formatOptions, 'txt'),
    'host_workers' => sanitizeInt($_POST['host_workers'] ?? 32, 32, 1, 512),
    'host_timeout' => sanitizeInt($_POST['host_timeout'] ?? 5, 5, 1, 120),
    'screenshot_workers' => sanitizeInt($_POST['screenshot_workers'] ?? 1, 1, 1, 16),
    'http_timeout' => sanitizeInt($_POST['http_timeout'] ?? 10, 10, 1, 120),
    'browser_timeout' => sanitizeInt($_POST['browser_timeout'] ?? 20, 20, 1, 300),
    'unicode' => isset($_POST['unicode']),
    'labels_only' => isset($_POST['labels_only']),
    'show_stats' => isset($_POST['show_stats']),
];

$activeTab = sanitizeChoice((string)($_GET['tab'] ?? 'dashboard'), $tabOptions, 'dashboard');
$launchResult = null;
$errorMessage = null;
$selectedMonitoredDomain = sanitizeDomainDirectoryName((string)($_GET['domain'] ?? ''));
$perPageOptions = [10, 50, 100];
$perPage = sanitizeInt($_GET['per_page'] ?? 10, 10, 1, 1000);
if (!in_array($perPage, $perPageOptions, true)) {
    $perPage = 10;
}
$page = sanitizeInt($_GET['page'] ?? 1, 1, 1, 1000000);
$runStatusLabels = [
    'done' => $t('done'),
    'running' => $t('running_status'),
    'error' => $t('done_with_error'),
    'db_error' => $t('db_error'),
    'empty' => $t('not_available'),
];

$requestedAction = (string)($_GET['action'] ?? '');

if ($requestedAction === 'export_pdf') {
    $dbPath = getDomainDbPath($defaultOutputRoot, $selectedMonitoredDomain);
    if ($selectedMonitoredDomain === '' || $dbPath === null) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=UTF-8');
        echo $t('sqlite_not_found');
        exit;
    }
    try {
        exportReportPdf($selectedMonitoredDomain, $dbPath, $translations, $lang);
    } catch (Throwable $e) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=UTF-8');
        echo $t('report_pdf_error', ['message' => $e->getMessage()]);
        exit;
    }
} elseif ($requestedAction === 'export_all_pdf') {
    try {
        $exportJobs = listJobs($jobsDir);
        $exportRuns = enrichRunsWithDbStats(listRecentRuns($defaultOutputRoot), getLatestJobMap($exportJobs), $runStatusLabels);
        exportAllReportsPdf($exportRuns, $translations, $lang);
    } catch (Throwable $e) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=UTF-8');
        echo $t('report_pdf_error', ['message' => $e->getMessage()]);
        exit;
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $action = (string)($_POST['action'] ?? 'launch_scan');

    if ($action === 'update_status') {
        header('Content-Type: application/json; charset=UTF-8');
        $monitoredDomain = sanitizeDomainDirectoryName((string)($_POST['monitored_domain'] ?? ''));
        $checkingDomain = trim((string)($_POST['checking_domain'] ?? ''));
        $newStatus = (string)($_POST['new_status'] ?? '');

        if ($monitoredDomain === '' || $checkingDomain === '' || !array_key_exists($newStatus, $manualStatuses)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'message' => $t('invalid_request')], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $dbPath = getDomainDbPath($defaultOutputRoot, $monitoredDomain);
        if ($dbPath === null) {
            http_response_code(404);
            echo json_encode(['ok' => false, 'message' => $t('sqlite_not_found')], JSON_UNESCAPED_UNICODE);
            exit;
        }

        try {
            $result = updateDomainStatusInDb($dbPath, $checkingDomain, $newStatus, [
                'not_found' => $t('db_domain_not_found'),
                'already_set' => $t('status_already_set'),
                'updated' => $t('status_updated'),
            ]);
            if (isset($result['status'])) {
                $result['status_label'] = statusLabel($result['status'], $translations, $lang);
            }
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'message' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
        }
        exit;
    }

    if ($action === 'launch_scan') {
        $activeTab = 'scan';
        if ($form['domain'] === '') {
            $errorMessage = $t('domain_required');
        } else {
            $commandParts = buildCommandParts($form, $pythonScript);
            $launchResult = launchBackgroundJob($commandParts, $form, $jobsDir, $baseDir, $t('job_started'));
            if (!$launchResult['ok']) {
                $errorMessage = $t('job_start_failed');
            }
        }
    }
}

$jobs = listJobs($jobsDir);
$latestJobMap = getLatestJobMap($jobs);
$recentRuns = enrichRunsWithDbStats(listRecentRuns($defaultOutputRoot), $latestJobMap, $runStatusLabels);
$domainDetailStats = null;
$domainsPage = null;
$selectedDbPath = null;
if ($selectedMonitoredDomain !== '') {
    $selectedDbPath = getDomainDbPath($defaultOutputRoot, $selectedMonitoredDomain);
    if ($selectedDbPath !== null) {
        try {
            $domainDetailStats = getDomainSummaryStats($selectedDbPath);
            $domainsPage = getPaginatedDomainEntries($selectedDbPath, $page, $perPage);
        } catch (Throwable $e) {
            $errorMessage = $t('sqlite_read_error', ['message' => $e->getMessage()]);
            $activeTab = 'dashboard';
        }
    }
}
?><!doctype html>
<html lang="<?= h($t('html_lang')) ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($t('app_title')) ?></title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
        .wrap { max-width: 1500px; margin: 0 auto; padding: 24px; }
        .topbar { display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; margin-bottom:18px; }
        h1 { margin: 0; font-size: 28px; }
        h2, h3 { margin-top: 0; }
        .card { background: #111827; border: 1px solid #1f2937; border-radius: 14px; padding: 18px; margin-bottom: 18px; box-shadow: 0 10px 24px rgba(0,0,0,.18); }
        .grid-2, .grid-3, .stats-grid { display:grid; gap:16px; }
        .grid-2 { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
        .grid-3 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
        .stats-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
        label, .field-label { display:block; font-weight:700; margin-bottom:6px; }
        input[type=text], input[type=number], select, textarea { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:10px; border:1px solid #334155; background:#0b1220; color:#e2e8f0; }
        .domain-input { font-size: 28px; padding:18px 20px; border-radius:14px; }
        button, .btn { display:inline-block; background:#2563eb; color:#fff; border:none; border-radius:10px; padding:10px 14px; text-decoration:none; cursor:pointer; font-weight:700; }
        .btn.secondary { background:#334155; }
        .checks { display:flex; gap:18px; flex-wrap:wrap; margin-top: 12px; }
        .checks label { font-weight:500; margin-bottom:0; }
        .ok { color:#22c55e; }
        .fail { color:#f87171; }
        .running { color:#facc15; }
        .muted { color:#94a3b8; }
        .small { font-size: 12px; }
        .alert { padding:12px 14px; border-radius:10px; margin-bottom:16px; }
        .alert.error { background:#450a0a; color:#fecaca; border:1px solid #7f1d1d; }
        .alert.success { background:#052e16; color:#bbf7d0; border:1px solid #166534; }
        table { width:100%; border-collapse: collapse; }
        th, td { text-align:left; padding:12px 10px; border-bottom:1px solid #1f2937; vertical-align: top; }
        .tabs { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
        .tab { padding:10px 14px; border-radius:999px; background:#1e293b; color:#cbd5e1; text-decoration:none; border:1px solid #334155; }
        .tab.active { background:#2563eb; color:#fff; border-color:#2563eb; }
        .lang-switch { display:flex; gap:6px; align-items:center; color:#94a3b8; font-size:13px; margin-left:6px; }
        .lang-switch a { color:#cbd5e1; text-decoration:none; border:1px solid #334155; border-radius:999px; padding:7px 9px; background:#1e293b; }
        .lang-switch a.active { color:#fff; background:#2563eb; border-color:#2563eb; }
        .hint { display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:50%; background:#334155; color:#fff; font-size:12px; font-weight:700; margin-left:6px; position:relative; cursor:help; }
        .tooltip { display:none; position:absolute; left:24px; top:-6px; width:280px; background:#020617; color:#e2e8f0; border:1px solid #334155; border-radius:10px; padding:10px 12px; z-index:100; font-weight:400; line-height:1.45; box-shadow:0 16px 28px rgba(0,0,0,.35); }
        .hint:hover .tooltip { display:block; }
        .controls { display:flex; gap:12px; flex-wrap:wrap; align-items:end; }
        .domain-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap:16px; }
        .domain-card { background:#0b1220; border:1px solid #1f2937; border-radius:14px; overflow:hidden; }
        .domain-shot { width:100%; display:block; background:#020617; aspect-ratio:4/3; object-fit:contain; }
        .domain-body { padding:14px; }
        .domain-title { font-size:18px; font-weight:700; margin:0 0 8px; word-break:break-all; }
        .domain-meta { display:grid; gap:6px; font-size:13px; color:#cbd5e1; }
        .pager { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-top:18px; }
        .pager a, .pager span { padding:8px 10px; border-radius:10px; background:#0b1220; border:1px solid #334155; color:#e2e8f0; text-decoration:none; }
        .pager .current { background:#2563eb; border-color:#2563eb; }
        .status-line { margin-top:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
        .status-message { font-size:12px; color:#93c5fd; }
        .status-badge { display:inline-block; padding:3px 8px; border-radius:999px; background:#1e293b; }
        .summary-tile { background:#0b1220; border:1px solid #1f2937; border-radius:12px; padding:14px; }
        .summary-tile strong { display:block; font-size:12px; color:#94a3b8; margin-bottom:6px; text-transform:uppercase; }
        .summary-tile span { font-size:20px; font-weight:700; }
        .hero-actions { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-top:16px; }
        details { background:#0b1220; border:1px solid #334155; border-radius:12px; padding:0 16px 16px; }
        summary { cursor:pointer; font-weight:700; padding:16px 0; }
        .page-title-row { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap; }
        .inline-links { display:flex; gap:10px; flex-wrap:wrap; }
        @media (max-width: 800px) { .domain-input { font-size: 22px; } }
    </style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div>
            <h1><?= h($t('app_title')) ?></h1>
            <div class="muted"><?= h($t('app_subtitle')) ?></div>
        </div>
        <div class="tabs">
            <a class="tab <?= $activeTab === 'dashboard' ? 'active' : '' ?>" href="<?= h(buildPageUrl(['tab' => 'dashboard', 'page' => null])) ?>"><?= h($t('dashboard')) ?></a>
            <a class="tab <?= $activeTab === 'scan' ? 'active' : '' ?>" href="<?= h(buildPageUrl(['tab' => 'scan', 'domain' => null, 'page' => null])) ?>"><?= h($t('scan_domain_tab')) ?></a>
            <div class="lang-switch" aria-label="<?= h($t('language')) ?>">
                <span><?= h($t('language')) ?>:</span>
                <a class="<?= $lang === 'en' ? 'active' : '' ?>" href="<?= h(buildPageUrl(['lang' => 'en'])) ?>">EN</a>
                <a class="<?= $lang === 'ru' ? 'active' : '' ?>" href="<?= h(buildPageUrl(['lang' => 'ru'])) ?>">RU</a>
            </div>
        </div>
    </div>

    <?php if ($errorMessage): ?>
        <div class="alert error"><?= h($errorMessage) ?></div>
    <?php endif; ?>
    <?php if ($launchResult && !empty($launchResult['ok'])): ?>
        <div class="alert success">
            <?= h($launchResult['message']) ?>
            <div class="small" style="margin-top:6px;">Job ID: <strong><?= h($launchResult['job_id']) ?></strong>, PID: <strong><?= h($launchResult['pid']) ?></strong></div>
        </div>
    <?php endif; ?>

    <?php if ($activeTab === 'scan'): ?>
        <div class="card">
            <div class="page-title-row">
                <div>
                    <h2 style="margin-bottom:6px;"><?= h($t('scan_request_title')) ?></h2>
                    <div class="muted"><?= h($t('scan_request_subtitle')) ?></div>
                </div>
            </div>
            <form method="post">
                <input type="hidden" name="action" value="launch_scan">
                <div>
                    <label class="field-label" for="domain"><?= h($t('domain')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['domain'] ?? '') ?></span></span></label>
                    <input class="domain-input" type="text" id="domain" name="domain" placeholder="<?= h($t('domain_placeholder')) ?>" value="<?= h($form['domain']) ?>" required>
                </div>
                <div class="hero-actions">
                    <button type="submit"><?= h($t('run_scan')) ?></button>
                </div>
                <details style="margin-top:18px;">
                    <summary><?= h($t('advanced_settings')) ?></summary>
                    <div class="grid-3">
                        <div>
                            <label class="field-label" for="tlds"><?= h($t('tld_file')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['tlds'] ?? '') ?></span></span></label>
                            <select id="tlds" name="tlds">
                                <?php foreach ($wordlistFiles as $item): ?>
                                    <option value="<?= h($item['relative']) ?>" <?= $form['tlds'] === $item['relative'] ? 'selected' : '' ?>><?= h($item['name']) ?> — <?= h($item['relative']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="field-label" for="keywords"><?= h($t('keywords_file')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['keywords'] ?? '') ?></span></span></label>
                            <select id="keywords" name="keywords">
                                <?php foreach ($wordlistFiles as $item): ?>
                                    <option value="<?= h($item['relative']) ?>" <?= $form['keywords'] === $item['relative'] ? 'selected' : '' ?>><?= h($item['name']) ?> — <?= h($item['relative']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="field-label" for="mode"><?= h($t('mode')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['mode'] ?? '') ?></span></span></label>
                            <select id="mode" name="mode">
                                <?php foreach ($modeOptions as $option): ?>
                                    <option value="<?= h($option) ?>" <?= $form['mode'] === $option ? 'selected' : '' ?>><?= h($option) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="field-label" for="keyword_target"><?= h($t('keyword_target')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['keyword_target'] ?? '') ?></span></span></label>
                            <select id="keyword_target" name="keyword_target">
                                <?php foreach ($keywordTargetOptions as $option): ?>
                                    <option value="<?= h($option) ?>" <?= $form['keyword_target'] === $option ? 'selected' : '' ?>><?= h($option) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="field-label" for="format"><?= h($t('output_format')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['format'] ?? '') ?></span></span></label>
                            <select id="format" name="format">
                                <?php foreach ($formatOptions as $option): ?>
                                    <option value="<?= h($option) ?>" <?= $form['format'] === $option ? 'selected' : '' ?>><?= h($option) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="field-label" for="host_workers"><?= h($t('host_workers')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['host_workers'] ?? '') ?></span></span></label>
                            <input type="number" id="host_workers" name="host_workers" min="1" max="512" value="<?= h($form['host_workers']) ?>">
                        </div>
                        <div>
                            <label class="field-label" for="host_timeout"><?= h($t('host_timeout')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['host_timeout'] ?? '') ?></span></span></label>
                            <input type="number" id="host_timeout" name="host_timeout" min="1" max="120" value="<?= h($form['host_timeout']) ?>">
                        </div>
                        <div>
                            <label class="field-label" for="screenshot_workers"><?= h($t('screenshot_workers')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['screenshot_workers'] ?? '') ?></span></span></label>
                            <input type="number" id="screenshot_workers" name="screenshot_workers" min="1" max="16" value="<?= h($form['screenshot_workers']) ?>">
                        </div>
                        <div>
                            <label class="field-label" for="http_timeout"><?= h($t('http_timeout')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['http_timeout'] ?? '') ?></span></span></label>
                            <input type="number" id="http_timeout" name="http_timeout" min="1" max="120" value="<?= h($form['http_timeout']) ?>">
                        </div>
                        <div>
                            <label class="field-label" for="browser_timeout"><?= h($t('browser_timeout')) ?><span class="hint">?<span class="tooltip"><?= h($tooltips['browser_timeout'] ?? '') ?></span></span></label>
                            <input type="number" id="browser_timeout" name="browser_timeout" min="1" max="300" value="<?= h($form['browser_timeout']) ?>">
                        </div>
                    </div>
                    <div class="checks">
                        <label><input type="checkbox" name="unicode" <?= $form['unicode'] ? 'checked' : '' ?>> <?= h($t('unicode_homoglyphs')) ?> <span class="hint">?<span class="tooltip"><?= h($tooltips['unicode'] ?? '') ?></span></span></label>
                        <label><input type="checkbox" name="labels_only" <?= $form['labels_only'] ? 'checked' : '' ?>> <?= h($t('labels_only')) ?> <span class="hint">?<span class="tooltip"><?= h($tooltips['labels_only'] ?? '') ?></span></span></label>
                        <label><input type="checkbox" name="show_stats" <?= $form['show_stats'] ? 'checked' : '' ?>> <?= h($t('show_stats')) ?> <span class="hint">?<span class="tooltip"><?= h($tooltips['show_stats'] ?? '') ?></span></span></label>
                    </div>
                </details>
            </form>
        </div>
    <?php else: ?>
        <?php if ($selectedMonitoredDomain !== '' && $selectedDbPath && $domainsPage): ?>
            <div class="card">
                <div class="page-title-row">
                    <div>
                        <div class="inline-links small" style="margin-bottom:8px;"><a class="btn secondary" href="<?= h(buildPageUrl(['tab' => 'dashboard', 'domain' => null, 'page' => null, 'action' => null])) ?>">← <?= h($t('back_to_dashboard')) ?></a></div>
                        <h2 style="margin-bottom:6px;"><?= h($selectedMonitoredDomain) ?></h2>
                        <div class="muted"><?= h($t('domain_detail_subtitle')) ?></div>
                    </div>
                    <div class="inline-links">
                        <a class="btn secondary" href="<?= h(buildPageUrl(['action' => 'export_pdf', 'domain' => $selectedMonitoredDomain, 'tab' => 'dashboard'])) ?>"><?= h($t('export_pdf')) ?></a>
                        <a class="btn secondary" href="/results/<?= h(rawurlencode($selectedMonitoredDomain)) ?>/<?= h(rawurlencode($selectedMonitoredDomain)) ?>.sqlite3" target="_blank"><?= h($t('open_sqlite')) ?></a>
                    </div>
                </div>
                <div class="stats-grid" style="margin-top:14px;">
                    <div class="summary-tile"><strong><?= h($t('first_check')) ?></strong><span><?= h($domainDetailStats['first_check'] ?? $t('not_available')) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('last_check')) ?></strong><span><?= h($domainDetailStats['last_check'] ?? $t('not_available')) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('generated')) ?></strong><span><?= h((int)($domainDetailStats['generated_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('live')) ?></strong><span><?= h((int)($domainDetailStats['live_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('screenshots')) ?></strong><span><?= h((int)($domainDetailStats['screenshot_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('unchecked')) ?></strong><span><?= h((int)($domainDetailStats['unchecked_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('true_positive')) ?></strong><span><?= h((int)($domainDetailStats['true_positive_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('false_positive')) ?></strong><span><?= h((int)($domainDetailStats['false_positive_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('selling')) ?></strong><span><?= h((int)($domainDetailStats['selling_total'] ?? 0)) ?></span></div>
                    <div class="summary-tile"><strong><?= h($t('no_dns')) ?></strong><span><?= h((int)($domainDetailStats['no_dns_total'] ?? 0)) ?></span></div>
                </div>
            </div>
            <div class="card">
                <div class="page-title-row">
                    <div>
                        <h3><?= h($t('found_domains_screenshots')) ?></h3>
                        <div class="muted"><?= h($t('screenshot_records_total', ['total' => $domainsPage['total']])) ?></div>
                    </div>
                    <form method="get" class="controls">
                        <input type="hidden" name="tab" value="dashboard">
                        <input type="hidden" name="domain" value="<?= h($selectedMonitoredDomain) ?>">
                        <input type="hidden" name="lang" value="<?= h($lang) ?>">
                        <div>
                            <label for="per_page"><?= h($t('per_page')) ?></label>
                            <select name="per_page" id="per_page" onchange="this.form.submit()">
                                <?php foreach ($perPageOptions as $option): ?>
                                    <option value="<?= h($option) ?>" <?= $perPage === $option ? 'selected' : '' ?>><?= h($option) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </form>
                </div>
                <?php if (!$domainsPage['rows']): ?>
                    <p class="muted"><?= h($t('no_screenshots_yet')) ?></p>
                <?php else: ?>
                    <div class="domain-grid">
                        <?php foreach ($domainsPage['rows'] as $row): ?>
                            <div class="domain-card">
                                <img class="domain-shot" src="data:image/png;base64,<?= h($row['Screenshot']) ?>" alt="<?= h($row['Checking domain']) ?>">
                                <div class="domain-body">
                                    <div class="domain-title"><?= h($row['Checking domain']) ?></div>
                                    <div class="domain-meta">
                                        <div><strong><?= h($t('status')) ?>:</strong> <span class="status-badge current-status"><?= h(statusLabel($row['Status'] ?? null, $translations, $lang)) ?></span></div>
                                        <div><strong><?= h($t('ip')) ?>:</strong> <?= h($row['IP address'] ?: $t('not_available')) ?></div>
                                        <div><strong><?= h($t('final_url')) ?>:</strong> <?= $row['Final URL'] ? '<a href="' . h($row['Final URL']) . '" target="_blank">' . h($row['Final URL']) . '</a>' : '<span class="muted">' . h($t('not_available')) . '</span>' ?></div>
                                        <div><strong><?= h($t('http')) ?>:</strong> <?= h($row['HTTP Status Code'] ?: $t('not_available')) ?></div>
                                        <div><strong><?= h($t('first_check')) ?>:</strong> <?= h($row['First Check Date'] ?: $t('not_available')) ?></div>
                                        <div><strong><?= h($t('first_live')) ?>:</strong> <?= h($row['First live appear date'] ?: $t('not_available')) ?></div>
                                        <div><strong><?= h($t('last_check')) ?>:</strong> <?= h($row['Last check date'] ?: $t('not_available')) ?></div>
                                    </div>
                                    <div class="status-line">
                                        <select class="status-select" data-monitored-domain="<?= h($selectedMonitoredDomain) ?>" data-checking-domain="<?= h($row['Checking domain']) ?>">
                                            <option value=""><?= h($t('choose_status')) ?></option>
                                            <?php foreach ($manualStatuses as $statusValue => $statusLabel): ?>
                                                <option value="<?= h($statusValue) ?>" <?= $row['Status'] === $statusValue ? 'selected' : '' ?>><?= h($statusLabel) ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <span class="status-message"></span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <?php if ($domainsPage['page_count'] > 1): ?>
                        <div class="pager">
                            <?php if ($domainsPage['page'] > 1): ?>
                                <a href="<?= h(buildPageUrl(['tab' => 'dashboard', 'domain' => $selectedMonitoredDomain, 'per_page' => $perPage, 'page' => $domainsPage['page'] - 1])) ?>">← <?= h($t('previous')) ?></a>
                            <?php endif; ?>
                            <?php for ($p = 1; $p <= $domainsPage['page_count']; $p++): ?>
                                <?php if ($p === $domainsPage['page']): ?>
                                    <span class="current"><?= h($p) ?></span>
                                <?php else: ?>
                                    <a href="<?= h(buildPageUrl(['tab' => 'dashboard', 'domain' => $selectedMonitoredDomain, 'per_page' => $perPage, 'page' => $p])) ?>"><?= h($p) ?></a>
                                <?php endif; ?>
                            <?php endfor; ?>
                            <?php if ($domainsPage['page'] < $domainsPage['page_count']): ?>
                                <a href="<?= h(buildPageUrl(['tab' => 'dashboard', 'domain' => $selectedMonitoredDomain, 'per_page' => $perPage, 'page' => $domainsPage['page'] + 1])) ?>"><?= h($t('next')) ?> →</a>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="card">
                <div class="page-title-row">
                    <div>
                        <h2><?= h($t('dashboard')) ?></h2>
                        <p class="muted"><?= h($t('dashboard_intro')) ?></p>
                    </div>
                    <?php if ($recentRuns): ?>
                        <a class="btn secondary" href="<?= h(buildPageUrl(['action' => 'export_all_pdf', 'tab' => 'dashboard', 'domain' => null, 'page' => null])) ?>"><?= h($t('export_all_pdf')) ?></a>
                    <?php endif; ?>
                </div>
                <?php if (!$recentRuns): ?>
                    <p class="muted"><?= h($t('no_saved_runs', ['path' => $defaultOutputRoot])) ?></p>
                <?php else: ?>
                    <table>
                        <thead>
                        <tr>
                            <th><?= h($t('checked_domain')) ?></th>
                            <th><?= h($t('status')) ?></th>
                            <th><?= h($t('first_check')) ?></th>
                            <th><?= h($t('last_check')) ?></th>
                            <th><?= h($t('generated')) ?></th>
                            <th><?= h($t('live')) ?></th>
                            <th><?= h($t('screenshots')) ?></th>
                            <th><?= h($t('latest_output')) ?></th>
                            <th><?= h($t('sqlite')) ?></th>
                            <th><?= h($t('updated')) ?></th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($recentRuns as $run): ?>
                            <tr>
                                <td><a href="<?= h(buildPageUrl(['tab' => 'dashboard', 'domain' => $run['domain'], 'page' => null])) ?>"><strong><?= h($run['domain']) ?></strong></a></td>
                                <td>
                                    <span class="<?= h($run['status_class']) ?>"><?= h($run['status_label']) ?></span>
                                    <?php if (!empty($run['status_log'])): ?>
                                        <div class="small muted"><a href="/results/_jobs/<?= h(rawurlencode($run['status_log'])) ?>" target="_blank"><?= h($t('log')) ?></a></div>
                                    <?php endif; ?>
                                </td>
                                <td><?= h($run['first_check'] ?: $t('not_available')) ?></td>
                                <td><?= h($run['last_check'] ?: $t('not_available')) ?></td>
                                <td><?= h($run['generated_total'] ?? $t('not_available')) ?></td>
                                <td><?= h($run['live_total'] ?? $t('not_available')) ?></td>
                                <td><?= h($run['screenshot_count']) ?></td>
                                <td>
                                    <?php if ($run['latest_output']): ?>
                                        <a href="/results/<?= h(rawurlencode($run['domain'])) ?>/<?= h(rawurlencode(basename($run['latest_output']))) ?>" target="_blank"><?= h(basename($run['latest_output'])) ?></a>
                                    <?php else: ?>
                                        <span class="muted"><?= h($t('none')) ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($run['sqlite']): ?>
                                        <a href="/results/<?= h(rawurlencode($run['domain'])) ?>/<?= h(rawurlencode(basename($run['sqlite']))) ?>" target="_blank"><?= h(basename($run['sqlite'])) ?></a>
                                    <?php else: ?>
                                        <span class="muted"><?= h($t('none')) ?></span>
                                    <?php endif; ?>
                                </td>
                                <td><?= $run['mtime'] ? h(date('Y-m-d H:i:s', $run['mtime'])) : '<span class="muted">' . h($t('not_available')) . '</span>' ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>
<script>
const statusMessages = {
    saving: <?= json_encode($t('status_saving'), JSON_UNESCAPED_UNICODE) ?>,
    saved: <?= json_encode($t('status_saved'), JSON_UNESCAPED_UNICODE) ?>,
    error: <?= json_encode($t('status_update_error'), JSON_UNESCAPED_UNICODE) ?>
};
document.querySelectorAll('.status-select').forEach(function(select) {
    select.addEventListener('change', function() {
        if (!this.value) return;
        const card = this.closest('.domain-card');
        const messageNode = card.querySelector('.status-message');
        const badgeNode = card.querySelector('.current-status');
        const formData = new FormData();
        formData.append('action', 'update_status');
        formData.append('monitored_domain', this.dataset.monitoredDomain || '');
        formData.append('checking_domain', this.dataset.checkingDomain || '');
        formData.append('new_status', this.value);
        messageNode.textContent = statusMessages.saving;
        fetch(<?= json_encode('/?lang=' . rawurlencode($lang), JSON_UNESCAPED_UNICODE) ?>, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'fetch' }
        })
        .then(function(response) { return response.json(); })
        .then(function(data) {
            if (!data.ok) {
                throw new Error(data.message || statusMessages.error);
            }
            badgeNode.textContent = data.status_label || data.status || select.value;
            messageNode.textContent = statusMessages.saved;
            setTimeout(function() { messageNode.textContent = ''; }, 1600);
        })
        .catch(function(error) {
            messageNode.textContent = error.message || statusMessages.error;
        });
    });
});
<div style="position:fixed;bottom:0;width:100%;text-align:center;padding:10px;"> Made in Russia with Love <a 
href="https://hydrattack.com" target="_blank" style="color:#007BFF;text-decoration:none;">HydrAttack.com</a></div>
</script>
</body>
</html>
