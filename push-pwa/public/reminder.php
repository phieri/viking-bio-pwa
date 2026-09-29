<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

use VikingBioPush\PushSender;
use VikingBioPush\VapidConfig;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$secret = trim((string) getenv('PUSH_REMINDER_SECRET'));
if ($secret === '') {
    http_response_code(503);
    echo json_encode(['error' => 'Reminder is not configured']);
    exit;
}

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches) !== 1 || !hash_equals($secret, $matches[1])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require dirname(__DIR__) . '/vendor/autoload.php';

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.yaml', new VapidConfig(__DIR__ . '/../storage/vapid.json'));
$reminderState = new \VikingBioPush\ReminderState(__DIR__ . '/../storage/reminder-state.json');

if (!$reminderState->shouldSendNow()) {
    http_response_code(200);
    echo json_encode([
        'ok' => false,
        'skipped' => true,
        'type' => 'weekly_cleaning_reminder',
        'reason' => 'already_sent_within_week',
        'last_sent_at' => $reminderState->lastSentAt(),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$result = $sender->sendWeeklyCleaningReminder();
$reminderState->recordSent();

echo json_encode([
    'ok' => true,
    'type' => 'weekly_cleaning_reminder',
    ...$result,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
