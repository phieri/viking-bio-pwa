<?php

declare(strict_types=1);

session_start();

$uiUrl = getenv('PUSH_UI_URL') ?: (getenv('APP_URL') ?: 'http://localhost:8000');
if (empty($_SESSION['push_send_token'])) {
    $_SESSION['push_send_token'] = bin2hex(random_bytes(32));
}

header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'uiUrl' => $uiUrl,
    'sendToken' => $_SESSION['push_send_token'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
