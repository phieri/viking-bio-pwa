<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$statePath = __DIR__ . '/../storage/last-contact.json';
if (!is_file($statePath)) {
    echo json_encode([
        'lastContact' => null,
        'devices' => [],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$raw = file_get_contents($statePath);
if ($raw === false || trim($raw) === '') {
    echo json_encode([
        'lastContact' => null,
        'devices' => [],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$decoded = json_decode($raw, true);
if (!is_array($decoded)) {
    echo json_encode([
        'lastContact' => null,
        'devices' => [],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$latest = null;
$devices = [];
foreach ($decoded as $device => $entry) {
    if (!is_array($entry)) {
        continue;
    }

    $timestamp = $entry['timestamp'] ?? null;
    if (!is_numeric($timestamp)) {
        continue;
    }

    $deviceTimestamp = (int) $timestamp;
    $devices[(string) $device] = [
        'device' => (string) ($entry['device'] ?? $device),
        'timestamp' => $deviceTimestamp,
        'type' => $entry['type'] ?? 'heartbeat',
        'detail' => $entry['detail'] ?? 'alive',
    ];

    if ($latest === null || $deviceTimestamp > $latest) {
        $latest = $deviceTimestamp;
    }
}

echo json_encode([
    'lastContact' => $latest,
    'devices' => $devices,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
