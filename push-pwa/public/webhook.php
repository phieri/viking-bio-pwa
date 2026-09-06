<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\PushSender;
use VikingBioPush\VapidConfig;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$expectedToken = trim((string) getenv('PUSH_WEBHOOK_TOKEN'));
if ($expectedToken === '') {
    http_response_code(503);
    echo json_encode(['error' => 'Webhook receiver is not configured']);
    exit;
}

$providedToken = '';
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches) === 1) {
    $providedToken = trim($matches[1]);
}
if ($providedToken === '') {
    $providedToken = trim((string) ($_SERVER['HTTP_X_WEBHOOK_TOKEN'] ?? ($_GET['token'] ?? '')));
}
if (!hash_equals($expectedToken, $providedToken)) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$body = file_get_contents('php://input');
if ($body === false || trim($body) === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Request body required']);
    exit;
}

$payload = json_decode($body, true);
if (!is_array($payload)) {
    http_response_code(400);
    echo json_encode(['error' => 'JSON request body required']);
    exit;
}

$device = is_string($payload['device'] ?? null) ? trim($payload['device']) : '';
$type = is_string($payload['type'] ?? null) ? strtolower(trim($payload['type'])) : '';
$detail = is_string($payload['detail'] ?? null) ? strtolower(trim($payload['detail'])) : '';
$errorCode = (int) ($payload['err'] ?? 0);
$temperature = isset($payload['temp']) && is_numeric($payload['temp']) ? (float) $payload['temp'] : null;

if ($device === '' || $type === '') {
    http_response_code(400);
    echo json_encode(['error' => 'device and type are required']);
    exit;
}

$title = 'Viking Bio alert';
$message = 'New burner status update received.';
$priority = 'normal';

switch ($type) {
    case 'flame':
        if ($detail === 'on') {
            $title = 'Burner started';
            $message = sprintf('Flame detected on %s.', $device);
            $priority = 'high';
        } elseif ($detail === 'off') {
            $title = 'Burner stopped';
            $message = sprintf('Flame cleared on %s.', $device);
        } else {
            $message = sprintf('Flame state changed on %s.', $device);
        }
        break;

    case 'error':
        $priority = 'high';
        if ($detail === 'stale') {
            $title = 'Telemetry lost';
            $message = sprintf('No fresh telemetry received from %s.', $device);
        } elseif ($errorCode > 0) {
            $title = 'Burner error';
            $message = sprintf('Device %s reported error code %d.', $device, $errorCode);
        } else {
            $title = 'Burner alert';
            $message = sprintf('Device %s reported an error state.', $device);
        }
        break;
}

if ($temperature !== null && $type !== 'error') {
    $message .= sprintf(' Temperature %.1f°C.', $temperature);
}

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.yaml', new VapidConfig(__DIR__ . '/../storage/vapid.json'));
$result = $sender->send(
    $title,
    $message,
    '/icon.svg',
    [
        'tag' => 'viking-bio-' . $type,
        'url' => getenv('PUSH_UI_URL') ?: (getenv('APP_URL') ?: '/'),
        'timestamp' => (int) floor(microtime(true) * 1000),
        'priority' => $priority,
        'device' => $device,
        'type' => $type,
        'detail' => $detail,
    ],
    $priority,
    $device
);

echo json_encode([
    'ok' => true,
    'device' => $device,
    'type' => $type,
    'detail' => $detail,
    'priority' => $priority,
    ...$result,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
