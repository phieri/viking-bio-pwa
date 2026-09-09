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
            'lastLfsHealth' => null,
            'lastCpuTemp' => null,
            'devices' => [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $raw = file_get_contents($statePath);
    if ($raw === false || trim($raw) === '') {
        echo json_encode([
            'lastContact' => null,
            'lastRssi' => null,
            'lastLfsHealth' => null,
            'lastCpuTemp' => null,
            'devices' => [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        echo json_encode([
            'lastContact' => null,
            'lastRssi' => null,
            'lastLfsHealth' => null,
            'lastCpuTemp' => null,
            'devices' => [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
}

$latest = null;
$latestRssi = null;
$latestLfsHealth = null;
$latestCpuTemp = null;
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

    $lfsHealth = isset($entry['lfsHealth']) ? filter_var($entry['lfsHealth'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : null;
    if ($lfsHealth === null && isset($entry['lfs_ok'])) {
        $lfsHealth = filter_var($entry['lfs_ok'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    }

    $cpuTemp = null;
    if (isset($entry['cpuTemp']) && is_numeric($entry['cpuTemp'])) {
        $cpuTemp = (float) $entry['cpuTemp'];
    } elseif (isset($entry['cpu_temp_c']) && is_numeric($entry['cpu_temp_c'])) {
        $cpuTemp = (float) $entry['cpu_temp_c'];
    }

    $deviceTimestamp = (int) $timestamp;
    $devices[(string) $device] = [
        'device' => (string) ($entry['device'] ?? $device),
        'timestamp' => $deviceTimestamp,
        'type' => $entry['type'] ?? 'heartbeat',
        'detail' => $entry['detail'] ?? 'alive',
        'rssi' => $rssi,
        'lfsHealth' => $lfsHealth,
        'cpuTemp' => $cpuTemp,
    ];

    if ($latest === null || $deviceTimestamp > $latest) {
        $latest = $deviceTimestamp;
        $latestRssi = $rssi;
        $latestLfsHealth = $lfsHealth;
        $latestCpuTemp = $cpuTemp;
    } elseif ($deviceTimestamp === $latest) {
        if ($rssi !== null) {
            $latestRssi = $rssi;
        }
        if ($lfsHealth !== null) {
            $latestLfsHealth = $lfsHealth;
        }
        if ($cpuTemp !== null) {
            $latestCpuTemp = $cpuTemp;
        }
    }
}

echo json_encode([
    'lastContact' => $latest,
    'lastRssi' => $latestRssi,
    'lastLfsHealth' => $latestLfsHealth,
    'lastCpuTemp' => $latestCpuTemp,
    'devices' => $devices,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
