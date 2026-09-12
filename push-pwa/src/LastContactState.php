<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

namespace VikingBioPush;

final class LastContactState
{
    private const string CACHE_KEY_PREFIX = 'viking-bio-last-contact:';
    private const int MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

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

    public function record(string $device, string $type, string $detail, ?int $rssi, ?bool $lfsHealth, ?array $extra = null): bool
    {
        $state = $this->load();
        $entry = [
            'device' => $device,
            'timestamp' => (int) floor(microtime(true) * 1000),
            'type' => $type,
            'detail' => $detail,
            'rssi' => $rssi,
            'lfsHealth' => $lfsHealth,
        ];

        if (is_array($extra)) {
            foreach ($extra as $key => $value) {
                if ($key === 'device' || $key === 'timestamp' || $key === 'type' || $key === 'detail' || $key === 'rssi' || $key === 'lfsHealth') {
                    continue;
                }
                $entry[$key] = $value;
            }
        }

        $state[$device] = $entry;
        return $this->write($state);
    }

    public function summary(): array
    {
        $latest = null;
        $latestRssi = null;
        $latestLfsHealth = null;
        $latestFlameOnMs = null;
        $latestWindowMs = null;
        $devices = [];

        foreach ($this->load() as $device => $entry) {
            $normalizedEntry = $this->normalizeEntry($device, $entry);
            if ($normalizedEntry === null) {
                continue;
            }

            $deviceTimestamp = $normalizedEntry['timestamp'];
            $devices[(string) $device] = $normalizedEntry;

            if ($latest === null || $deviceTimestamp > $latest) {
                $latest = $deviceTimestamp;
                $latestRssi = $normalizedEntry['rssi'];
                $latestLfsHealth = $normalizedEntry['lfsHealth'];
                $latestFlameOnMs = $normalizedEntry['flameOnMs'];
                $latestWindowMs = $normalizedEntry['windowMs'];
                continue;
            }

            if ($deviceTimestamp === $latest) {
                if ($normalizedEntry['rssi'] !== null) {
                    $latestRssi = $normalizedEntry['rssi'];
                }
                if ($normalizedEntry['lfsHealth'] !== null) {
                    $latestLfsHealth = $normalizedEntry['lfsHealth'];
                }
                if ($normalizedEntry['flameOnMs'] !== null) {
                    $latestFlameOnMs = $normalizedEntry['flameOnMs'];
                }
                if ($normalizedEntry['windowMs'] !== null) {
                    $latestWindowMs = $normalizedEntry['windowMs'];
                }
            }
        }

        return [
            'lastContact' => $latest,
            'lastRssi' => $latestRssi,
            'lastLfsHealth' => $latestLfsHealth,
            'lastFlameOnMs' => $latestFlameOnMs,
            'lastWindowMs' => $latestWindowMs,
            'devices' => $devices,
        ];
    }

    private function normalizeInt(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }

    private function load(): array
    {
        $mtime = is_file($this->path) ? filemtime($this->path) : false;
        if (function_exists('apcu_fetch')) {
            $cachedState = apcu_fetch($this->cacheKey(), $success);
            if ($success && is_array($cachedState) && ($cachedState['mtime'] ?? null) === $mtime && is_array($cachedState['state'] ?? null)) {
                return $cachedState['state'];
            }
        }

        $state = $this->loadFromFile();
        if (function_exists('apcu_store')) {
            apcu_store($this->cacheKey(), ['mtime' => $mtime, 'state' => $state], 86400);
        }

        return $state;
    }

    private function write(array $state): bool
    {
        $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return false;
        }

        $written = file_put_contents($this->path, $json . "\n", LOCK_EX);
        if ($written === false) {
            return false;
        }

        if (function_exists('apcu_store')) {
            $mtime = filemtime($this->path);
            apcu_store($this->cacheKey(), ['mtime' => $mtime, 'state' => $state], 86400);
        }

        return true;
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

    private function loadFromFile(): array
    {
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

    private function normalizeEntry(string|int $deviceKey, mixed $entry): ?array
    {
        if (!is_array($entry)) {
            return null;
        }

        $deviceTimestamp = $this->normalizeTimestamp($entry['timestamp'] ?? null);
        if ($deviceTimestamp === null) {
            return null;
        }

        $device = $this->normalizeString($entry['device'] ?? $deviceKey);
        if ($device === '') {
            return null;
        }

        return [
            'device' => $device,
            'timestamp' => $deviceTimestamp,
            'type' => $this->normalizeString($entry['type'] ?? 'heartbeat', 'heartbeat'),
            'detail' => $this->normalizeString($entry['detail'] ?? 'alive', 'alive'),
            'rssi' => $this->normalizeRssi($entry['rssi'] ?? null),
            'lfsHealth' => $this->normalizeLfsHealth($entry),
            'flameOnMs' => $this->normalizeInt($entry['flameOnMs'] ?? null),
            'windowMs' => $this->normalizeInt($entry['windowMs'] ?? null),
        ];
    }

    private function normalizeTimestamp(mixed $value): ?int
    {
        if (!is_int($value) && !is_string($value)) {
            return null;
        }

        $candidate = trim((string) $value);
        if ($candidate === '' || preg_match('/^-?\d+$/', $candidate) !== 1) {
            return null;
        }

        $timestamp = (int) $candidate;
        $maximumTimestamp = (int) floor(microtime(true) * 1000) + self::MAX_CLOCK_SKEW_MS;
        if ($timestamp < 0 || $timestamp > $maximumTimestamp) {
            return null;
        }

        return $timestamp;
    }

    private function normalizeString(mixed $value, string $fallback = ''): string
    {
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            return $fallback;
        }

        $normalized = trim((string) $value);
        return $normalized !== '' ? $normalized : $fallback;
    }

    private function cacheKey(): string
    {
        return self::CACHE_KEY_PREFIX . sha1($this->path);
    }
}
