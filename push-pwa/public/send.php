<?php

declare(strict_types=1);

session_start();
require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\PushSender;
use VikingBioPush\VapidConfig;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$allowedOrigin = getenv('APP_URL') ?: (getenv('PUSH_UI_URL') ?: 'http://localhost:8000');
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$referrer = $_SERVER['HTTP_REFERER'] ?? '';
$allowedHost = parse_url($allowedOrigin, PHP_URL_HOST) ?: 'localhost';

if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== $allowedHost) {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden origin']);
    exit;
}

if ($origin === '' && $referrer !== '' && parse_url($referrer, PHP_URL_HOST) !== $allowedHost) {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden referrer']);
    exit;
}

$expectedToken = $_SESSION['push_send_token'] ?? '';
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$providedToken = '';
if (preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches) === 1) {
    $providedToken = $matches[1];
}

if ($expectedToken === '' || !hash_equals($expectedToken, $providedToken)) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$body = file_get_contents('php://input');
if ($body === false || $body === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Request body required']);
    exit;
}

$data = json_decode($body, true);
if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['error' => 'JSON request body required']);
    exit;
}

$title = is_string($data['title'] ?? null) ? $data['title'] : 'Viking Bio alert';
$bodyText = is_string($data['body'] ?? null) ? $data['body'] : 'New status update';
$icon = is_string($data['icon'] ?? null) ? $data['icon'] : '/icon.svg';
$url = is_string($data['url'] ?? null) ? $data['url'] : (getenv('PUSH_UI_URL') ?: getenv('APP_URL') ?: '/');
$rawPriority = is_string($data['priority'] ?? null) ? strtolower($data['priority']) : 'normal';
$allowedPriorities = ['low', 'normal', 'high'];
if (!in_array($rawPriority, $allowedPriorities, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Priority must be one of low, normal, or high']);
    exit;
}
$priority = $rawPriority;

$sender = new PushSender(__DIR__ . '/../storage/subscriptions.json', new VapidConfig(__DIR__ . '/../storage/vapid.json'));
$result = $sender->send($title, $bodyText, $icon, ['tag' => 'viking-bio-alert', 'url' => $url], $priority);

echo json_encode(['ok' => true, 'priority' => $priority, ...$result], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
