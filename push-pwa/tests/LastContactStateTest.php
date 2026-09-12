<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\LastContactState;

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function assertSame(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . sprintf(' (expected %s, got %s)', var_export($expected, true), var_export($actual, true)));
    }
}

$tempDir = sys_get_temp_dir() . '/viking-bio-last-contact-' . bin2hex(random_bytes(6));
if (!mkdir($tempDir, 0700, true) && !is_dir($tempDir)) {
    throw new RuntimeException('Unable to create test directory');
}

$path = $tempDir . '/last-contact.json';
$state = new LastContactState($path);

assertTrue($state->record('device-a', 'heartbeat', 'alive', -71, true, ['flameOnMs' => 1000, 'windowMs' => 2000]), 'Expected first record write to succeed');
$summary = $state->summary();
assertSame(1, count($summary['devices']), 'Expected one device summary after first record');
assertSame('device-a', $summary['devices']['device-a']['device'], 'Expected device id to be preserved');
assertSame(-71, $summary['devices']['device-a']['rssi'], 'Expected RSSI to be normalised');
assertSame(true, $summary['devices']['device-a']['lfsHealth'], 'Expected LittleFS health to be preserved');

$invalidState = [
    'device-bad-timestamp' => [
        'device' => 'device-bad-timestamp',
        'timestamp' => 'not-a-number',
        'type' => 'heartbeat',
        'detail' => 'alive',
    ],
    'device-future' => [
        'device' => 'device-future',
        'timestamp' => (int) floor(microtime(true) * 1000) + 600000,
        'type' => 'heartbeat',
        'detail' => 'alive',
    ],
    'device-b' => [
        'device' => 'device-b',
        'timestamp' => (int) floor(microtime(true) * 1000) - 1000,
        'type' => 'heartbeat',
        'detail' => 'alive',
        'rssi' => '-55',
        'lfs_ok' => 'true',
    ],
];

file_put_contents($path, json_encode($invalidState, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
$reloaded = new LastContactState($path);
$summary = $reloaded->summary();

assertSame(1, count($summary['devices']), 'Expected invalid device entries to be ignored');
assertTrue(isset($summary['devices']['device-b']), 'Expected valid device entry to remain available');
assertSame(-55, $summary['devices']['device-b']['rssi'], 'Expected numeric string RSSI to be normalised');
assertSame(true, $summary['devices']['device-b']['lfsHealth'], 'Expected legacy lfs_ok field to be normalised');

unlink($path);
rmdir($tempDir);
