<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

namespace VikingBioPush;

final class LastContactState
{
    private const string CACHE_KEY = 'viking-bio-last-contact';

    public function __construct(private readonly string $path)
    {
        $directory = dirname($this->path);
        if ($directory !== '' && !is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        if (is_link($this->path) || (file_exists($this->path) && !is_file($this->path))) {
            throw new \RuntimeException('Last-contact state path must be a regular file');
        }
    }

    public function record(string $device, string $type, string $detail, ?int $rssi, ?bool $lfsHealth): bool
    {
        $state = $this->load();
        $state[$device] = [
            'device' => $device,
            'timestamp' => (int) floor(microtime(true) * 1000),
            'type' => $type,
            'detail' => $detail,
            'rssi' => $rssi,
            'lfsHealth' => $lfsHealth,
        ];

        return $this->write($state);
    }

    public function summary(): array
    {
        $latest = null;
        $latestRssi = null;
        $latestLfsHealth = null;
        $devices = [];

        foreach ($this->load() as $device => $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $timestamp = $entry['timestamp'] ?? null;
            if (!is_numeric($timestamp)) {
                continue;
            }

            $rssi = $this->normalizeRssi($entry['rssi'] ?? null);
            $lfsHealth = $this->normalizeLfsHealth($entry);
            $deviceTimestamp = (int) $timestamp;
            $devices[(string) $device] = [
                'device' => (string) ($entry['device'] ?? $device),
                'timestamp' => $deviceTimestamp,
                'type' => $entry['type'] ?? 'heartbeat',
                'detail' => $entry['detail'] ?? 'alive',
                'rssi' => $rssi,
                'lfsHealth' => $lfsHealth,
            ];

            if ($latest === null || $deviceTimestamp > $latest) {
                $latest = $deviceTimestamp;
                $latestRssi = $rssi;
                $latestLfsHealth = $lfsHealth;
                continue;
            }

            if ($deviceTimestamp === $latest) {
                if ($rssi !== null) {
                    $latestRssi = $rssi;
                }
                if ($lfsHealth !== null) {
                    $latestLfsHealth = $lfsHealth;
                }
            }
        }

        return [
            'lastContact' => $latest,
            'lastRssi' => $latestRssi,
            'lastLfsHealth' => $latestLfsHealth,
            'devices' => $devices,
        ];
    }

    private function load(): array
    {
        if (function_exists('apcu_fetch')) {
            $cachedState = apcu_fetch(self::CACHE_KEY, $success);
            return $success && is_array($cachedState) ? $cachedState : [];
        }

        if (!is_file($this->path)) {
            return [];
        }

        $rawState = file_get_contents($this->path);
        if ($rawState === false || trim($rawState) === '') {
            return [];
        }

        $decodedState = json_decode($rawState, true);
        return is_array($decodedState) ? $decodedState : [];
    }

    private function write(array $state): bool
    {
        if (function_exists('apcu_store')) {
            return apcu_store(self::CACHE_KEY, $state, 86400);
        }

        $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return false;
        }

        $written = file_put_contents($this->path, $json . "\n", LOCK_EX);
        return $written !== false;
    }

    private function normalizeRssi(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function normalizeLfsHealth(array $entry): ?bool
    {
        $value = $entry['lfsHealth'] ?? ($entry['lfs_ok'] ?? null);
        return isset($value)
            ? filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
            : null;
    }
}
