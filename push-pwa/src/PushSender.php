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
    public function send(string $title, string $body, ?string $icon = null, array $extra = [], ?string $priority = null, ?string $sender = null): array
    {
        $normalizedPriority = $priority !== null ? strtolower($priority) : null;
        if ($normalizedPriority !== null && !in_array($normalizedPriority, ['low', 'normal', 'high'], true)) {
            throw new \InvalidArgumentException('Priority must be one of low, normal, or high');
        }

        // A null sender means broadcast to every subscription. Explicit sender values are
        // matched case-insensitively so each browser client only receives the burner it chose.
        $normalizedSender = $sender !== null ? trim($sender) : null;
        if ($normalizedSender === '' || ($normalizedSender !== null && strtolower($normalizedSender) === 'all')) {
            $normalizedSender = null;
        }
        if ($normalizedSender !== null) {
            $normalizedSender = strtolower($normalizedSender);
        }

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

        $timezone = $this->resolveBridgeTimezone($extra);
        $payload = json_encode([
            'title' => $title,
            'body' => $body,
            'icon' => $icon ?? '/icon.svg',
            ...$this->stripTimezoneMetadata($extra),
            'timestamp' => $this->currentBridgeTimestamp($timezone),
        ], JSON_UNESCAPED_SLASHES);

        $sent = 0;
        $failed = 0;

        foreach ($subscriptions as $subscription) {
            $priorityValue = is_string($subscription['priority'] ?? null) ? strtolower($subscription['priority']) : 'normal';
            if ($normalizedPriority !== null && $priorityValue !== $normalizedPriority) {
                continue;
            }

            $subscriptionSender = $subscription['sender'] ?? null;
            if (is_string($subscriptionSender)) {
                $subscriptionSender = trim($subscriptionSender);
            } else {
                $subscriptionSender = '';
            }

            if ($normalizedSender !== null) {
                $subscriptionSenderLower = strtolower($subscriptionSender);
                // `sender: all` is a deliberate wildcard; otherwise a message is only sent to
                // subscriptions that explicitly match the requested sender value.
                if ($subscriptionSenderLower !== 'all' && ($subscriptionSender === '' || $subscriptionSenderLower !== $normalizedSender)) {
                    continue;
                }
            }

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

    private function resolveBridgeTimezone(array $extra): ?string
    {
        foreach (['timezone', 'tz'] as $key) {
            if (isset($extra[$key]) && is_string($extra[$key])) {
                $timezone = trim($extra[$key]);
                if ($timezone !== '') {
                    return $timezone;
                }
            }
        }

        foreach (['BRIDGE_TIMEZONE', 'TIMEZONE', 'TZ'] as $envName) {
            $timezone = getenv($envName);
            if (is_string($timezone) && trim($timezone) !== '') {
                return trim($timezone);
            }
        }

        return null;
    }

    private function currentBridgeTimestamp(?string $timezone): int
    {
        if ($timezone === null || $timezone === '') {
            return time();
        }

        try {
            return (new \DateTimeImmutable('now', new \DateTimeZone($timezone)))->getTimestamp();
        } catch (\Throwable) {
            return time();
        }
    }

    private function stripTimezoneMetadata(array $extra): array
    {
        $cleanExtra = $extra;
        unset($cleanExtra['timezone'], $cleanExtra['tz'], $cleanExtra['timestamp']);

        return $cleanExtra;
    }
}
