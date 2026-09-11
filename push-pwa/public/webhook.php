<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\LastContactState;
use VikingBioPush\PushSender;
use VikingBioPush\PushTranslations;
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
$flameOnPct = null;
if (array_key_exists('flame_on_pct', $payload) && is_numeric($payload['flame_on_pct'])) {
    $flameOnPct = (int) round((float) $payload['flame_on_pct']);
} elseif (array_key_exists('flameOnPct', $payload) && is_numeric($payload['flameOnPct'])) {
    $flameOnPct = (int) round((float) $payload['flameOnPct']);
}
$flameOnMs = null;
if (array_key_exists('flame_on_ms', $payload) && is_numeric($payload['flame_on_ms'])) {
    $flameOnMs = (int) $payload['flame_on_ms'];
} elseif (array_key_exists('flameOnMs', $payload) && is_numeric($payload['flameOnMs'])) {
    $flameOnMs = (int) $payload['flameOnMs'];
}
$windowMs = null;
if (array_key_exists('window_ms', $payload) && is_numeric($payload['window_ms'])) {
    $windowMs = (int) $payload['window_ms'];
} elseif (array_key_exists('windowMs', $payload) && is_numeric($payload['windowMs'])) {
    $windowMs = (int) $payload['windowMs'];
}

if ($device === '' || $type === '') {
    webhook_response_fail(400, 'device and type are required');
}

$priority = match ($type) {
    'flame' => $detail === 'on' ? 'high' : 'normal',
    'error' => 'high',
    'heartbeat' => 'very-low',
    default => 'normal',
};

$summary = [];
if ($type === 'heartbeat') {
    $summary['flameOnPct'] = $flameOnPct;
    $summary['flameOnMs'] = $flameOnMs;
    $summary['windowMs'] = $windowMs;

    $lastContactState = new LastContactState(__DIR__ . '/../storage/last-contact.json');
    if (!$lastContactState->record($device, $type, $detail, $rssi, $lfsHealth, $summary)) {
        webhook_response_fail(500, sprintf('Failed to persist last contact for %s', $device));
    }

    error_log(sprintf('webhook.php: heartbeat stored for %s (%s/%s)', $device, $type, $detail));
}

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.yaml', new VapidConfig(__DIR__ . '/../storage/vapid.json'));
$icon = PushSender::notificationIcon($type, $detail);
$result = $sender->sendTranslated(
    static fn (string $language, array $subscription): array => PushTranslations::webhookAlert($language, $type, $detail, $device, $errorCode, $temperature, $lfsHealth, $summary),
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
