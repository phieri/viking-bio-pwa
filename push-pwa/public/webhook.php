<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\PushSender;
use VikingBioPush\VapidConfig;

header('Content-Type: text/plain; charset=utf-8');

function webhook_response_ok(): never
{
    http_response_code(200);
    echo 'OK';
    exit;
}

function webhook_response_fail(int $statusCode, string $reason): never
{
    error_log('webhook.php: ' . $reason);
    http_response_code($statusCode);
    echo 'FAIL';
    exit;
}

function webhook_require_ipv6(): void
{
    $remoteAddress = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($remoteAddress === '') {
        return;
    }

    if (str_contains($remoteAddress, '.') || !filter_var($remoteAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        webhook_response_fail(403, 'IPv6-only webhook listener');
    }
}

webhook_require_ipv6();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    webhook_response_fail(405, 'Method not allowed');
}

$expectedToken = trim((string) getenv('PUSH_WEBHOOK_TOKEN'));
if ($expectedToken === '') {
    webhook_response_fail(503, 'Webhook receiver is not configured');
}

$providedToken = '';
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches) === 1) {
    $providedToken = trim($matches[1]);
}
if ($providedToken === '') {
    $providedToken = trim((string) ($_SERVER['HTTP_X_WEBHOOK_TOKEN'] ?? ''));
}
if (!hash_equals($expectedToken, $providedToken)) {
    webhook_response_fail(401, 'Unauthorized webhook token');
}

$body = file_get_contents('php://input');
if ($body === false || trim($body) === '') {
    webhook_response_fail(400, 'Request body required');
}

$payload = json_decode($body, true);
if (!is_array($payload)) {
    webhook_response_fail(400, 'JSON request body required');
}

$device = is_string($payload['device'] ?? null) ? trim($payload['device']) : '';
$type = is_string($payload['type'] ?? null) ? strtolower(trim($payload['type'])) : '';
$detail = is_string($payload['detail'] ?? null) ? strtolower(trim($payload['detail'])) : '';
$rssi = isset($payload['rssi']) && is_numeric($payload['rssi']) ? (int) $payload['rssi'] : null;
$lfsHealth = null;
if (array_key_exists('lfs_ok', $payload) && is_bool($payload['lfs_ok'])) {
    $lfsHealth = $payload['lfs_ok'];
} elseif (array_key_exists('lfs_ok', $payload) && is_numeric($payload['lfs_ok'])) {
    $lfsHealth = (bool) $payload['lfs_ok'];
}
$errorCode = (int) ($payload['err'] ?? 0);
$temperature = isset($payload['temp']) && is_numeric($payload['temp']) ? (float) $payload['temp'] : null;

if ($device === '' || $type === '') {
    webhook_response_fail(400, 'device and type are required');
}

$alert = match ($type) {
    'flame' => match (true) {
        $detail === 'on' => [
            'title' => 'Burner started',
            'message' => sprintf('Flame detected on %s.', $device),
            'priority' => 'high',
        ],
        $detail === 'off' => [
            'title' => 'Burner stopped',
            'message' => sprintf('Flame cleared on %s.', $device),
            'priority' => 'normal',
        ],
        default => [
            'title' => 'Viking Bio alert',
            'message' => sprintf('Flame state changed on %s.', $device),
            'priority' => 'normal',
        ],
    },
    'error' => match (true) {
        $detail === 'stale' => [
            'title' => 'Telemetry lost',
            'message' => sprintf('No fresh telemetry received from %s.', $device),
            'priority' => 'high',
        ],
        $errorCode > 0 => [
            'title' => 'Burner error',
            'message' => sprintf('Device %s reported error code %d.', $device, $errorCode),
            'priority' => 'high',
        ],
        default => [
            'title' => 'Burner alert',
            'message' => sprintf('Device %s reported an error state.', $device),
            'priority' => 'high',
        ],
    },
    'heartbeat' => [
        'title' => 'Burner heartbeat',
        'message' => sprintf('No alert activity has been reported by %s in the last 24 hours.', $device),
        'priority' => 'very-low',
    ],
    default => [
        'title' => 'Viking Bio alert',
        'message' => 'New burner status update received.',
        'priority' => 'normal',
    ],
};

$title = $alert['title'];
$message = $alert['message'];
$priority = $alert['priority'];
$urgency = $priority;

if ($temperature !== null && $type !== 'error') {
    $message .= sprintf(' Temperature %.1f°C.', $temperature);
}
if ($type === 'heartbeat' && $lfsHealth !== null) {
    $message .= sprintf(' LittleFS %s.', $lfsHealth ? 'healthy' : 'degraded');
}

if ($type === 'heartbeat') {
    $cacheKey = 'viking-bio-last-contact';
    $lastContactState = [];
    if (function_exists('apcu_fetch')) {
        $cachedState = apcu_fetch($cacheKey, $success);
        if ($success && is_array($cachedState)) {
            $lastContactState = $cachedState;
        }
    } else {
        $lastContactPath = __DIR__ . '/../storage/last-contact.json';
        if (is_file($lastContactPath)) {
            $rawState = file_get_contents($lastContactPath);
            if ($rawState !== false && trim($rawState) !== '') {
                $decodedState = json_decode($rawState, true);
                if (is_array($decodedState)) {
                    $lastContactState = $decodedState;
                }
            }
        }
    }

    $timestamp = (int) floor(microtime(true) * 1000);
    $lastContactState[$device] = [
        'device' => $device,
        'timestamp' => $timestamp,
        'type' => $type,
        'detail' => $detail,
        'rssi' => $rssi,
        'lfsHealth' => $lfsHealth,
    ];

    $writeOk = false;
    if (function_exists('apcu_store')) {
        $writeOk = apcu_store($cacheKey, $lastContactState, 86400);
    } else {
        $lastContactPath = __DIR__ . '/../storage/last-contact.json';
        $writeOk = file_put_contents(
            $lastContactPath,
            json_encode($lastContactState, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
            LOCK_EX
        ) !== false;
    }

    if (!$writeOk) {
        webhook_response_fail(500, sprintf('Failed to persist last contact for %s', $device));
    }

    error_log(sprintf('webhook.php: heartbeat stored for %s (%s/%s)', $device, $type, $detail));
    webhook_response_ok();
}

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.yaml', new VapidConfig(__DIR__ . '/../storage/vapid.json'));
$icon = PushSender::notificationIcon($type, $detail);
$result = $sender->send(
    $title,
    $message,
    $icon,
    [
        'tag' => 'viking-bio-' . $type,
        'url' => PushSender::uiUrl(),
        'timestamp' => (int) floor(microtime(true) * 1000),
        'device' => $device,
        'type' => $type,
        'detail' => $detail,
    ],
    $priority,
    $device
);

if (!is_array($result) || !isset($result['sent'], $result['failed'])) {
    webhook_response_fail(500, sprintf('Unexpected push result for %s', $device));
}

error_log(sprintf('webhook.php: delivered %s to %s (%d sent, %d failed)', $type, $device, $result['sent'], $result['failed']));
webhook_response_ok();
