<?php

declare(strict_types=1);

function requestEndpoint(string $file, string $method, array $environment = [], string $authorization = ''): array
{
    $script = '$_SERVER["REQUEST_METHOD"] = ' . var_export($method, true) . ';'
        . '$_SERVER["HTTP_AUTHORIZATION"] = ' . var_export($authorization, true) . ';'
        . 'register_shutdown_function(static function (): void { echo "\nSTATUS:" . (http_response_code() ?: 200); });'
        . 'include ' . var_export(dirname(__DIR__) . '/public/' . $file, true) . ';';
    $process = proc_open([PHP_BINARY, '-r', $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), array_merge($_ENV, $environment));
    if (!is_resource($process)) {
        throw new RuntimeException('Could not launch PHP endpoint');
    }
    $output = stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    if (proc_close($process) !== 0 || !preg_match('/\nSTATUS:(\d+)$/', $output, $matches)) {
        throw new RuntimeException('PHP endpoint failed: ' . $errors);
    }
    return [(int) $matches[1], json_decode(substr($output, 0, -strlen($matches[0])), true, 512, JSON_THROW_ON_ERROR)];
}

[$code, $body] = requestEndpoint('status.php', 'GET');
if ($code !== 200 || array_keys($body) !== ['lastContact', 'lastRssi', 'lastLfsHealth']) {
    throw new RuntimeException('GET status must return only approved fields');
}
[$code] = requestEndpoint('status.php', 'POST');
if ($code !== 405) {
    throw new RuntimeException('Status must reject writes');
}

[$code] = requestEndpoint('reminder.php', 'POST', ['PUSH_REMINDER_SECRET' => '']);
if ($code !== 503) {
    throw new RuntimeException('Reminder must fail closed without a configured secret');
}
[$code] = requestEndpoint('reminder.php', 'GET', ['PUSH_REMINDER_SECRET' => 'secret']);
if ($code !== 405) {
    throw new RuntimeException('Reminder must reject GET');
}
[$code] = requestEndpoint('reminder.php', 'POST', ['PUSH_REMINDER_SECRET' => 'secret']);
if ($code !== 401) {
    throw new RuntimeException('Reminder must reject missing authentication');
}
[$code] = requestEndpoint('reminder.php', 'POST', ['PUSH_REMINDER_SECRET' => 'secret'], '******');
if ($code !== 401) {
    throw new RuntimeException('Reminder must reject invalid authentication');
}

echo "Public endpoint validation checks passed\n";
