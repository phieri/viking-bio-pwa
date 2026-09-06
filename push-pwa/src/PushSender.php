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

        $payload = json_encode([
            'title' => $title,
            'body' => $body,
            'icon' => $icon ?? '/icon.svg',
            ...$extra,
        ], JSON_UNESCAPED_SLASHES);

        $sent = 0;
        $failed = 0;
        $pendingReports = [];

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

            $pendingReports[] = $endpoint;

            try {
                $webPush->sendNotification($endpoint, $payload, $userPublicKey, $userAuth, ['TTL' => 2419200]);
            } catch (\Throwable $throwable) {
                if ($this->isPermanentThrowableError($throwable)) {
                    $storage->removeEndpoint($endpoint);
                }
                continue;
            }
        }

        $reports = $webPush->flush();
        if (is_array($reports)) {
            foreach ($reports as $index => $report) {
                $reportEndpoint = $pendingReports[$index] ?? null;
                if ($this->isPermanentError($report)) {
                    if (is_string($reportEndpoint)) {
                        $storage->removeEndpoint($reportEndpoint);
                    }
                    $failed++;
                    continue;
                }

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

    private function isPermanentThrowableError(\Throwable $throwable): bool
    {
        $message = strtolower($throwable->getMessage());

        return str_contains($message, '410')
            || str_contains($message, '404')
            || str_contains($message, 'gone')
            || str_contains($message, 'not found')
            || str_contains($message, 'invalid subscription')
            || str_contains($message, 'subscription expired');
    }

    private function isPermanentError(mixed $report): bool
    {
        if (!is_object($report)) {
            return false;
        }

        foreach (['isSubscriptionExpired', 'isSubscriptionInvalid', 'isExpired', 'isInvalidSubscription'] as $method) {
            if (method_exists($report, $method) && $report->$method() === true) {
                return true;
            }
        }

        if (method_exists($report, 'getStatusCode')) {
            $statusCode = $report->getStatusCode();
            if (is_int($statusCode) && in_array($statusCode, [400, 404, 410], true)) {
                return true;
            }
            if (is_string($statusCode) && in_array((int) $statusCode, [400, 404, 410], true)) {
                return true;
            }
        }

        if (method_exists($report, 'getError')) {
            $error = $report->getError();
            if (!is_string($error)) {
                return false;
            }

            $normalized = strtolower($error);
            return str_contains($normalized, 'not found')
                || str_contains($normalized, 'gone')
                || str_contains($normalized, 'invalid subscription')
                || str_contains($normalized, 'subscription expired');
        }

        return false;
    }
}
