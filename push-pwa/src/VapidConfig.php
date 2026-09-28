<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

namespace VikingBioPush;

use Minishlink\WebPush\WebPush;

final class VapidConfig
{
    public function __construct(
        private readonly string $storagePath,
        private readonly string $subject = 'mailto:ops@example.com'
    ) {
    }

    public function publicKey(): string
    {
        return $this->resolve()['publicKey'];
    }

    public function privateKey(): string
    {
        return $this->resolve()['privateKey'];
    }

    public function subject(): string
    {
        return $this->resolve()['subject'];
    }

    private function resolve(): array
    {
        $publicKey = getenv('VAPID_PUBLIC_KEY');
        $privateKey = getenv('VAPID_PRIVATE_KEY');
        $subject = getenv('VAPID_SUBJECT') ?: $this->subject;

        if ($publicKey && $privateKey) {
            return ['publicKey' => $publicKey, 'privateKey' => $privateKey, 'subject' => $subject];
        }

        $dir = dirname($this->storagePath);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Unable to create VAPID configuration directory');
        }
        if (is_link($this->storagePath) || (file_exists($this->storagePath) && !is_file($this->storagePath))) {
            throw new \RuntimeException('VAPID configuration path must be a regular file');
        }

        if (file_exists($this->storagePath)) {
            $storedConfig = file_get_contents($this->storagePath);
            if (is_string($storedConfig) && $storedConfig !== '' && json_validate($storedConfig)) {
                try {
                    $data = json_decode($storedConfig, true, 512, JSON_THROW_ON_ERROR);
                } catch (\JsonException) {
                    $data = null;
                }
                if (is_array($data) && !empty($data['publicKey']) && !empty($data['privateKey'])) {
                    $this->secureStorageFile();
                    return [
                        'publicKey' => (string) $data['publicKey'],
                        'privateKey' => (string) $data['privateKey'],
                        'subject' => (string) ($data['subject'] ?? $subject),
                    ];
                }
            }
        }

        [$publicKey, $privateKey] = WebPush::createVapidKeys();
        $config = [
            'publicKey' => $publicKey,
            'privateKey' => $privateKey,
            'subject' => $subject,
        ];

        $json = json_encode($config, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (file_put_contents($this->storagePath, $json, LOCK_EX) === false) {
            throw new \RuntimeException('Unable to write VAPID configuration');
        }
        $this->secureStorageFile();

        return $config;
    }

    private function secureStorageFile(): void
    {
        if (chmod($this->storagePath, 0600) !== false) {
            return;
        }

        if (is_file($this->storagePath) && unlink($this->storagePath) === false) {
            throw new \RuntimeException('Unable to secure VAPID configuration permissions or remove the unsecured file');
        }

        throw new \RuntimeException('Unable to secure VAPID configuration file permissions');
    }
}
