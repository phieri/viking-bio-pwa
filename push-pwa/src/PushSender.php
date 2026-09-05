<?php

declare(strict_types=1);

namespace VikingBioPush;

use Minishlink\WebPush\WebPush;

final class PushSender
{
    public function __construct(
        private readonly string $storagePath,
        private readonly VapidConfig $vapidConfig
    ) {
    }

    /**
     * @return array{sent:int, failed:int}
     */
    public function send(string $title, string $body, ?string $icon = null, array $extra = []): array
    {
        $storage = new PushStorage($this->storagePath);
        $subscriptions = $storage->all();

        if ($subscriptions === []) {
            return ['sent' => 0, 'failed' => 0];
        }

        $webPush = new WebPush([
            'VAPID' => [
                'subject' => $this->vapidConfig->subject(),
                'publicKey' => $this->vapidConfig->publicKey(),
                'privateKey' => $this->vapidConfig->privateKey(),
            ],
        ]);

        $payload = json_encode([
            'title' => $title,
            'body' => $body,
            'icon' => $icon ?? '/icon.svg',
            ...$extra,
        ], JSON_UNESCAPED_SLASHES);

        $sent = 0;
        $failed = 0;

        foreach ($subscriptions as $subscription) {
            $endpoint = $subscription['endpoint'] ?? null;
            $keys = $subscription['keys'] ?? [];
            $userPublicKey = $keys['p256dh'] ?? null;
            $userAuth = $keys['auth'] ?? null;

            if (!is_string($endpoint) || !is_string($userPublicKey) || !is_string($userAuth)) {
                $failed++;
                continue;
            }

            try {
                $webPush->sendNotification($endpoint, $payload, $userPublicKey, $userAuth, ['TTL' => 2419200]);
            } catch (\Throwable $throwable) {
                continue;
            }
        }

        $reports = $webPush->flush();
        if (is_array($reports)) {
            foreach ($reports as $report) {
                if (is_object($report) && method_exists($report, 'isSuccess')) {
                    if ($report->isSuccess()) {
                        $sent++;
                    } else {
                        $failed++;
                    }
                    continue;
                }

                $failed++;
            }
        }

        return ['sent' => $sent, 'failed' => $failed];
    }
}
