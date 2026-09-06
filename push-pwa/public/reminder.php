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

$secret = getenv('PUSH_REMINDER_SECRET');
if ($secret !== false && $secret !== '') {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches) || !hash_equals($secret, $matches[1])) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
}

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.yaml', new VapidConfig(__DIR__ . '/../storage/vapid.json'));
$result = $sender->sendWeeklyCleaningReminder();

echo json_encode([
    'ok' => true,
    'type' => 'weekly_cleaning_reminder',
    ...$result,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
