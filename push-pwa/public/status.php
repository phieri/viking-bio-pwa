<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

require dirname(__DIR__) . '/src/LastContactState.php';

use VikingBioPush\LastContactState;

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET');
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

try {
    $status = (new LastContactState(__DIR__ . '/../storage/last-contact.json'))->publicStatus();
    echo json_encode($status, JSON_THROW_ON_ERROR);
} catch (\Throwable $exception) {
    error_log('status.php: unable to read last-contact state: ' . $exception->getMessage());
    http_response_code(503);
    echo json_encode(['error' => 'Status unavailable']);
}
