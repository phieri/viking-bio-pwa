<?php

declare(strict_types=1);

namespace VikingBioPush;

final class PushStorage
{
    public function __construct(private readonly string $path)
    {
        $directory = dirname($this->path);
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        if (!file_exists($this->path)) {
            file_put_contents($this->path, "");
            chmod($this->path, 0600);
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        $contents = file_get_contents($this->path);
        if ($contents === false || trim($contents) === '') {
            return [];
        }

        $subscriptions = [];
        $currentEndpoint = null;
        $currentKeys = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }

            if (str_ends_with($trimmed, ':')) {
                if ($currentEndpoint !== null) {
                    $subscriptions[] = ['endpoint' => $currentEndpoint, 'keys' => $currentKeys];
                }

                $currentEndpoint = $this->unescapeYamlScalar(substr($trimmed, 0, -1));
                $currentKeys = [];
                continue;
            }

            if ($currentEndpoint === null || !str_contains($trimmed, ':')) {
                continue;
            }

            [$key, $value] = array_map('trim', explode(':', $trimmed, 2));
            if ($key === 'auth' || $key === 'p256dh') {
                $currentKeys[$key] = $this->unescapeYamlScalar($value);
            }
        }

        if ($currentEndpoint !== null) {
            $subscriptions[] = ['endpoint' => $currentEndpoint, 'keys' => $currentKeys];
        }

        return $subscriptions;
    }

    public function upsert(array $subscription): void
    {
        $endpoint = $subscription['endpoint'] ?? null;
        if (!is_string($endpoint) || $endpoint === '') {
            throw new \InvalidArgumentException('Missing subscription endpoint');
        }

        $subscriptions = $this->all();
        $filtered = [];
        foreach ($subscriptions as $item) {
            if (($item['endpoint'] ?? null) !== $endpoint) {
                $filtered[] = $item;
            }
        }

        $filtered[] = $subscription;
        $this->write($filtered);
    }

    /**
     * @param array<int, array<string, mixed>> $subscriptions
     */
    public function write(array $subscriptions): void
    {
        $lines = [];
        foreach ($subscriptions as $subscription) {
            $endpoint = $subscription['endpoint'] ?? null;
            $keys = $subscription['keys'] ?? [];
            if (!is_string($endpoint) || $endpoint === '') {
                continue;
            }

            $lines[] = $this->yamlString($endpoint) . ':';
            $lines[] = '  auth: ' . $this->yamlString((string) ($keys['auth'] ?? ''));
            $lines[] = '  p256dh: ' . $this->yamlString((string) ($keys['p256dh'] ?? ''));
        }

        file_put_contents($this->path, implode("\n", $lines) . (count($lines) > 0 ? "\n" : ""));
        chmod($this->path, 0600);
    }

    private function yamlString(string $value): string
    {
        if ($value === '') {
            return '""';
        }

        if (preg_match('/^[A-Za-z0-9_\-./:]+$/', $value) === 1) {
            return $value;
        }

        return '"' . str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $value) . '"';
    }

    private function unescapeYamlScalar(string $value): string
    {
        $trimmed = trim($value);
        if (($trimmed[0] ?? '') === '"' && substr($trimmed, -1) === '"') {
            $trimmed = substr($trimmed, 1, -1);
        }

        return str_replace(['\\\\', '\\"', '\\n'], ['\\', '"', "\n"], $trimmed);
    }
}
