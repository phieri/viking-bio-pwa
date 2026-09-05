<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\PushStorage;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$body = file_get_contents('php://input');
if ($body === false || $body === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Request body required']);
    exit;
}

$data = json_decode($body, true);
if (!is_array($data) || !isset($data['subscription'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Subscription payload required']);
    exit;
}

try {
    $storage = new PushStorage(__DIR__ . '/../storage/subscriptions.yml');
    $storage->upsert($data['subscription']);
    echo json_encode(['ok' => true], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    http_response_code(400);
    echo json_encode(['error' => 'Failed to save subscription']);
}
