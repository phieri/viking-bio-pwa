<?php

declare(strict_types=1);

namespace VikingBioPush;

final class ReminderState
{
    public function __construct(private readonly string $path)
    {
        $directory = dirname($this->path);
        if ($directory !== '' && !is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        if (is_link($this->path) || (file_exists($this->path) && !is_file($this->path))) {
            throw new \RuntimeException('Reminder state path must be a regular file');
        }
    }

    public function shouldSendNow(): bool
    {
        $lastSentAt = $this->lastSentAt();
        if ($lastSentAt === null) {
            return true;
        }

        return (time() - $lastSentAt) >= (7 * 24 * 60 * 60);
    }

    public function recordSent(): void
    {
        $payload = ['last_sent_at' => time()];
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Unable to encode reminder state');
        }

        $written = file_put_contents($this->path, $json . "\n");
        if ($written === false) {
            throw new \RuntimeException('Unable to write reminder state');
        }

        chmod($this->path, 0600);
    }

    public function lastSentAt(): ?int
    {
        if (!is_file($this->path)) {
            return null;
        }

        $contents = file_get_contents($this->path);
        if ($contents === false || trim($contents) === '') {
            return null;
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            return null;
        }

        $value = $decoded['last_sent_at'] ?? null;
        if (!is_int($value) && !is_float($value) && !is_string($value)) {
            return null;
        }

        $timeValue = (int) $value;
        return $timeValue > 0 ? $timeValue : null;
    }
}
