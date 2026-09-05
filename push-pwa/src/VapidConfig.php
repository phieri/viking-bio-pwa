<?php

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

    /**
     * @return array{publicKey:string, privateKey:string, subject:string}
     */
    private function resolve(): array
    {
        $publicKey = getenv('VAPID_PUBLIC_KEY');
        $privateKey = getenv('VAPID_PRIVATE_KEY');
        $subject = getenv('VAPID_SUBJECT') ?: $this->subject;

        if ($publicKey && $privateKey) {
            return ['publicKey' => $publicKey, 'privateKey' => $privateKey, 'subject' => $subject];
        }

        $dir = dirname($this->storagePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        if (file_exists($this->storagePath)) {
            $data = json_decode((string) file_get_contents($this->storagePath), true);
            if (is_array($data) && !empty($data['publicKey']) && !empty($data['privateKey'])) {
                return [
                    'publicKey' => (string) $data['publicKey'],
                    'privateKey' => (string) $data['privateKey'],
                    'subject' => (string) ($data['subject'] ?? $subject),
                ];
            }
        }

        [$publicKey, $privateKey] = WebPush::createVapidKeys();
        $config = [
            'publicKey' => $publicKey,
            'privateKey' => $privateKey,
            'subject' => $subject,
        ];

        file_put_contents($this->storagePath, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        chmod($this->storagePath, 0600);

        return $config;
    }
}
