<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$cacheKey = 'viking-bio-last-contact';
$decoded = [];
if (function_exists('apcu_fetch')) {
    $cached = apcu_fetch($cacheKey, $success);
    if ($success && is_array($cached)) {
        $decoded = $cached;
    }
} else {
    $statePath = __DIR__ . '/../storage/last-contact.json';
    if (!is_file($statePath)) {
        echo json_encode([
            'lastContact' => null,
            'lastRssi' => null,
            'devices' => [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $raw = file_get_contents($statePath);
    if ($raw === false || trim($raw) === '') {
        echo json_encode([
            'lastContact' => null,
            'lastRssi' => null,
            'devices' => [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        echo json_encode([
            'lastContact' => null,
            'lastRssi' => null,
            'devices' => [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
}

$latest = null;
$latestRssi = null;
$devices = [];
foreach ($decoded as $device => $entry) {
    if (!is_array($entry)) {
        continue;
    }

    $timestamp = $entry['timestamp'] ?? null;
    if (!is_numeric($timestamp)) {
        continue;
    }

    $rssi = $entry['rssi'] ?? null;
    if (is_numeric($rssi)) {
        $rssi = (int) $rssi;
    } else {
        $rssi = null;
    }

    $deviceTimestamp = (int) $timestamp;
    $devices[(string) $device] = [
        'device' => (string) ($entry['device'] ?? $device),
        'timestamp' => $deviceTimestamp,
        'type' => $entry['type'] ?? 'heartbeat',
        'detail' => $entry['detail'] ?? 'alive',
        'rssi' => $rssi,
    ];

    if ($latest === null || $deviceTimestamp > $latest) {
        $latest = $deviceTimestamp;
        $latestRssi = $rssi;
    } elseif ($deviceTimestamp === $latest && $rssi !== null) {
        $latestRssi = $rssi;
    }
}

echo json_encode([
    'lastContact' => $latest,
    'lastRssi' => $latestRssi,
    'devices' => $devices,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
