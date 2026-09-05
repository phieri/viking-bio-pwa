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
            file_put_contents($this->path, "[]");
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

        $data = json_decode($contents, true);
        if (!is_array($data)) {
            return [];
        }

        return array_values(array_filter($data, static fn ($row) => is_array($row)));
    }

    public function upsert(array $subscription): void
    {
        $endpoint = $subscription['endpoint'] ?? null;
        if (!is_string($endpoint) || $endpoint === '') {
            throw new \InvalidArgumentException('Missing subscription endpoint');
        }

        $subscriptions = $this->all();
        $updated = [];
        foreach ($subscriptions as $item) {
            if (($item['endpoint'] ?? null) !== $endpoint) {
                $updated[] = $item;
            }
        }

        $updated[] = $subscription;
        $this->write($updated);
    }

    /**
     * @param array<int, array<string, mixed>> $subscriptions
     */
    public function write(array $subscriptions): void
    {
        $json = json_encode($subscriptions, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Unable to encode subscriptions');
        }

        file_put_contents($this->path, $json . "\n");
        chmod($this->path, 0600);
    }
}
