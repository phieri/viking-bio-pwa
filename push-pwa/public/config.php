<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
]);
session_start();

$uiUrl = getenv('PUSH_UI_URL') ?: (getenv('APP_URL') ?: \VikingBioPush\PushSender::uiUrl());
$uiUrl = \VikingBioPush\PushSender::normalizeUiTargetUrl($uiUrl, \VikingBioPush\PushSender::uiUrl());
if (empty($_SESSION['push_send_token'])) {
    $_SESSION['push_send_token'] = bin2hex(random_bytes(32));
}

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
echo json_encode([
    'uiUrl' => $uiUrl,
    'sendToken' => $_SESSION['push_send_token'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
