<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

session_start();
require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\PushSender;
use VikingBioPush\PushTranslations;
use VikingBioPush\VapidConfig;

function send_json_response(int $statusCode, array $payload): never
{
    http_response_code($statusCode);
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function send_parse_sender(mixed $value): ?string
{
    if (!is_string($value)) {
        return null;
    }

    $sender = trim($value);
    return $sender !== '' ? $sender : null;
}

function send_parse_priority(mixed $value): string
{
    if (!is_string($value)) {
        return 'normal';
    }

    $priority = strtolower(trim($value));
    if (!in_array($priority, PushSender::VALID_PRIORITIES, true)) {
        send_json_response(400, ['error' => 'Priority must be one of very-low, low, normal, or high']);
    }

    return $priority;
}

function send_parse_ui_target(mixed $value): string
{
    $safeUiUrl = PushSender::uiUrl();
    $target = is_string($value) ? $value : $safeUiUrl;
    return PushSender::normalizeUiTargetUrl($target, $safeUiUrl);
}

function send_decode_request_body(): array
{
    $body = file_get_contents('php://input');
    if ($body === false || $body === '') {
        send_json_response(400, ['error' => 'Request body required']);
    }

    $data = json_decode($body, true);
    if (!is_array($data)) {
        send_json_response(400, ['error' => 'JSON request body required']);
    }

    return $data;
}

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_json_response(405, ['error' => 'Method not allowed']);
}

$allowedOrigin = getenv('PUSH_UI_URL') ?: \VikingBioPush\PushSender::uiUrl();
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$referrer = $_SERVER['HTTP_REFERER'] ?? '';
$allowedHost = strtolower((string) (parse_url($allowedOrigin, PHP_URL_HOST) ?: 'localhost'));

$originHost = $origin !== '' ? strtolower((string) (parse_url($origin, PHP_URL_HOST) ?: '')) : '';
$referrerHost = $referrer !== '' ? strtolower((string) (parse_url($referrer, PHP_URL_HOST) ?: '')) : '';

if ($origin !== '' && $originHost !== $allowedHost) {
    send_json_response(403, ['error' => 'Forbidden origin']);
}

if ($origin === '' && $referrer !== '' && $referrerHost !== $allowedHost) {
    send_json_response(403, ['error' => 'Forbidden referrer']);
}

$expectedToken = $_SESSION['push_send_token'] ?? '';
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$providedToken = '';
if (preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches) === 1) {
    $providedToken = $matches[1];
}

if ($expectedToken === '' || !hash_equals($expectedToken, $providedToken)) {
    send_json_response(401, ['error' => 'Unauthorized']);
}

$data = send_decode_request_body();

$rawType = $data['type'] ?? null;
$type = is_string($rawType) ? strtolower(trim($rawType)) : '';

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.yaml', new VapidConfig(__DIR__ . '/../storage/vapid.json'));

if ($type === 'weekly_cleaning_reminder' || $type === 'cleaning-reminder' || $type === 'cleaning_reminder') {
    $reminderState = new \VikingBioPush\ReminderState(__DIR__ . '/../storage/reminder-state.json');

    if (!$reminderState->shouldSendNow()) {
        send_json_response(200, [
            'ok' => false,
            'skipped' => true,
            'type' => 'weekly_cleaning_reminder',
            'reason' => 'already_sent_within_week',
            'last_sent_at' => $reminderState->lastSentAt(),
        ]);
    }

    $senderValue = send_parse_sender($data['sender'] ?? null);

    $result = $sender->sendWeeklyCleaningReminder($senderValue);
    $reminderState->recordSent();
    send_json_response(200, ['ok' => true, 'type' => 'weekly_cleaning_reminder', 'sender' => $senderValue, ...$result]);
}

if ($type === 'test_alert' || $type === 'test-alert' || $type === 'test') {
    $senderValue = send_parse_sender($data['sender'] ?? null);
    $priority = send_parse_priority($data['priority'] ?? 'normal');
    $url = send_parse_ui_target($data['url'] ?? null);
    $sentAt = (int) floor(microtime(true) * 1000);
    $result = $sender->sendTranslated(
        static fn (string $language, array $subscription): array => PushTranslations::testNotification($language),
        '/icon.svg',
        ['tag' => 'viking-bio-alert', 'url' => $url, 'timestamp' => $sentAt],
        $priority,
        $senderValue
    );

    send_json_response(200, ['ok' => true, 'type' => 'test_alert', 'priority' => $priority, 'sender' => $senderValue, ...$result]);
}

$title = is_string($data['title'] ?? null) ? $data['title'] : 'Viking Bio alert';
$bodyText = is_string($data['body'] ?? null) ? $data['body'] : 'New status update';
$icon = is_string($data['icon'] ?? null) ? $data['icon'] : '/icon.svg';
$url = send_parse_ui_target($data['url'] ?? null);
$priority = send_parse_priority($data['priority'] ?? 'normal');
$urgency = $priority;

$senderValue = send_parse_sender($data['sender'] ?? null);

$sentAt = (int) floor(microtime(true) * 1000);

$result = $sender->send(
    $title,
    $bodyText,
    $icon,
    ['tag' => 'viking-bio-alert', 'url' => $url, 'timestamp' => $sentAt],
    $priority,
    $senderValue
);

send_json_response(200, ['ok' => true, 'priority' => $priority, 'urgency' => $urgency, 'sender' => $senderValue, ...$result]);
