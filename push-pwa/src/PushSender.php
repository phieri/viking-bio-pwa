<?php

declare(strict_types=1);

namespace VikingBioPush;

use Minishlink\WebPush\WebPush;

final class PushSender
{
    public const array VALID_PRIORITIES = ['very-low', 'low', 'normal', 'high'];

    public function __construct(
        private readonly string $storagePath,
        private readonly VapidConfig $vapidConfig
    ) {
    }

    /**
     * Returns the notification icon path for a given alert type and detail string.
     * Falls back to '/icon.svg' for unrecognised combinations.
     */
    public static function notificationIcon(string $type, string $detail = ''): string
    {
        return match (true) {
            $type === 'flame' && $detail === 'on'  => '/icons/fire.svg',
            $type === 'flame' && $detail === 'off' => '/icons/smoke.svg',
            $type === 'error'                       => '/icons/warning.svg',
            default                                 => '/icon.svg',
        };
    }

    public static function uiUrl(): string
    {
        $configuredUrl = getenv('PUSH_UI_URL');
        if (is_string($configuredUrl) && trim($configuredUrl) !== '') {
            $normalizedConfiguredUrl = trim($configuredUrl);
            return self::normalizeUiTargetUrl($normalizedConfiguredUrl, $normalizedConfiguredUrl);
        }

        $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
        if (is_string($host) && str_contains($host, ',')) {
            $host = trim(explode(',', $host)[0]);
        }
        $host = trim((string) $host);
        if ($host === '') {
            $host = 'localhost';
        }

        $host = self::canonicaliseHost($host);

        $protocol = isset($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off' ? 'https' : 'http';

        return $protocol . '://' . $host;
    }

    public static function normalizeUiTargetUrl(string $targetUrl, string $fallbackUrl = ''): string
    {
        $safeFallback = $fallbackUrl !== '' ? $fallbackUrl : self::uiUrl();
        $candidate = trim($targetUrl);
        if ($candidate === '') {
            return $safeFallback;
        }

        if (preg_match('/^[\/?#]/', $candidate) === 1) {
            return $candidate;
        }

        $parsed = parse_url($candidate);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            return $safeFallback;
        }

        $scheme = strtolower((string) $parsed['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return $safeFallback;
        }

        $fallbackHost = parse_url($safeFallback, PHP_URL_HOST);
        $candidateHost = strtolower((string) $parsed['host']);
        if ($fallbackHost === false || $fallbackHost === '' || $candidateHost !== strtolower((string) $fallbackHost)) {
            return $safeFallback;
        }

        $path = $parsed['path'] ?? '/';
        $query = isset($parsed['query']) ? '?' . $parsed['query'] : '';
        $fragment = isset($parsed['fragment']) ? '#' . $parsed['fragment'] : '';

        return $scheme . '://' . $candidateHost . $path . $query . $fragment;
    }

    private static function canonicaliseHost(string $host): string
    {
        $host = strtolower(trim($host));
        if ($host === '') {
            return 'localhost';
        }

        if (str_starts_with($host, '[') && str_contains($host, ']')) {
            $host = trim($host, '[]');
            return '[' . $host . ']';
        }

        $parsed = parse_url('http://' . $host);
        $parsedHost = is_array($parsed) ? $parsed['host'] ?? null : null;
        if (is_string($parsedHost) && $parsedHost !== '') {
            $port = $parsed['port'] ?? null;
            if (is_int($port) && $port > 0 && !in_array($port, [80, 443], true)) {
                return strtolower($parsedHost) . ':' . $port;
            }

            return strtolower($parsedHost);
        }

        if (preg_match('/^[A-Za-z0-9.-]+$/', $host) !== 1 && !preg_match('/^localhost$/i', $host)) {
            return 'localhost';
        }

        return $host;
    }

    public function sendWeeklyCleaningReminder(?string $sender = null): array
    {
        $sentAt = (int) floor(microtime(true) * 1000);

        return $this->send(
            'Weekly cleaning reminder',
            'Time for your weekly burner cleaning reminder.',
            '/icons/broom.svg',
            [
                'tag' => 'viking-bio-cleaning-reminder',
                'url' => self::uiUrl(),
                'timestamp' => $sentAt,
                'priority' => 'low',
            ],
            'low',
            $sender
        );
    }

    public function send(string $title, string $body, ?string $icon = null, array $extra = [], ?string $priority = null, ?string $sender = null): array
    {
        // The bridge/backend contract uses the generic "priority" term, but the Web Push
        // API itself expects the field name "urgency" when sending to the browser push
        // service. We normalize both values to the same four-level scale.
        $normalizedPriority = $this->normalizePriority($priority);
        $normalizedSender = $this->normalizeSender($sender);
        $normalizedUrgency = $this->normalizeUrgency($normalizedPriority);

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

        $payload = $this->buildPayload($title, $body, $icon, array_merge($extra, ['urgency' => $normalizedUrgency]));
        $deliveryState = $this->queuePendingNotifications($webPush, $payload, $subscriptions, $normalizedPriority, $normalizedSender, $storage);

        return $this->processDeliveryReports($webPush->flush(), $deliveryState['pendingReports'], $deliveryState['failed'], $storage);
    }

    private function normalizePriority(?string $priority): ?string
    {
        if ($priority === null) {
            return null;
        }

        $normalizedPriority = strtolower(trim($priority));

        return match ($normalizedPriority) {
            'very-low', 'low', 'normal', 'high' => $normalizedPriority,
            default => throw new \InvalidArgumentException('Priority must be one of very-low, low, normal, or high'),
        };
    }

    private function normalizeUrgency(?string $priority): ?string
    {
        if ($priority === null) {
            return null;
        }

        return match ($priority) {
            'very-low', 'low', 'normal', 'high' => $priority,
            default => throw new \InvalidArgumentException('Urgency must be one of very-low, low, normal, or high'),
        };
    }

    private function normalizeSender(?string $sender): ?string
    {
        // A null sender means broadcast to every subscription. Explicit sender values are
        // matched case-insensitively so each browser client only receives the burner it chose.
        $normalizedSender = $sender !== null ? trim($sender) : null;
        if ($normalizedSender === '' || ($normalizedSender !== null && strtolower($normalizedSender) === 'all')) {
            return null;
        }

        return $normalizedSender !== null ? strtolower($normalizedSender) : null;
    }

    private function buildPayload(string $title, string $body, ?string $icon, array $extra): string
    {
        return json_encode([
            'title' => $title,
            'body' => $body,
            'icon' => $icon ?? '/icon.svg',
            ...$extra,
        ], JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param array<int, array<string, mixed>> $subscriptions
     * @return array{pendingReports: array<int, string>, failed: int}
     */
    private function queuePendingNotifications(WebPush $webPush, string $payload, array $subscriptions, ?string $requestedPriority, ?string $requestedSender, PushStorage $storage): array
    {
        $pendingReports = [];
        $failed = 0;

        foreach ($subscriptions as $subscription) {
            if (!$this->canSendToSubscription($subscription, $requestedPriority, $requestedSender)) {
                continue;
            }

            $delivery = $this->extractSubscriptionDelivery($subscription);
            if ($delivery === null) {
                $failed++;
                continue;
            }

            $pendingReports[] = $delivery['endpoint'];

            try {
                $notificationOptions = ['TTL' => 86400];
                $webPushUrgency = $this->normalizeUrgency($requestedPriority);
                if ($webPushUrgency !== null) {
                    $notificationOptions['urgency'] = $webPushUrgency;
                }

                $webPush->sendNotification(
                    $delivery['endpoint'],
                    $payload,
                    $delivery['publicKey'],
                    $delivery['auth'],
                    $notificationOptions
                );
            } catch (\Throwable $throwable) {
                if ($this->isPermanentThrowableError($throwable)) {
                    $storage->removeEndpoint($delivery['endpoint']);
                }
            }
        }

        return ['pendingReports' => $pendingReports, 'failed' => $failed];
    }

    /**
     * @param array<string, mixed> $subscription
     */
    private function canSendToSubscription(array $subscription, ?string $requestedPriority, ?string $requestedSender): bool
    {
        $notificationLevel = $subscription['notificationLevel'] ?? null;
        if ($requestedPriority !== null && !$this->matchesNotificationLevel($notificationLevel, $requestedPriority)) {
            return false;
        }

        if ($requestedSender === null) {
            return true;
        }

        $subscriptionSender = $subscription['sender'] ?? null;
        if (!is_string($subscriptionSender)) {
            $subscriptionSender = '';
        }

        $subscriptionSender = trim($subscriptionSender);
        $subscriptionSenderLower = strtolower($subscriptionSender);

        return $subscriptionSenderLower === 'all' || ($subscriptionSender !== '' && $subscriptionSenderLower === $requestedSender);
    }

    /**
     * @param array<string, mixed> $subscription
     * @return array{endpoint:string,publicKey:string,auth:string}|null
     */
    private function extractSubscriptionDelivery(array $subscription): ?array
    {
        $endpoint = $subscription['endpoint'] ?? null;
        $keys = $subscription['keys'] ?? [];
        $userPublicKey = $keys['p256dh'] ?? null;
        $userAuth = $keys['auth'] ?? null;

        if (!is_string($endpoint) || !is_string($userPublicKey) || !is_string($userAuth)) {
            return null;
        }

        return [
            'endpoint' => $endpoint,
            'publicKey' => $userPublicKey,
            'auth' => $userAuth,
        ];
    }

    /**
     * @param array<int, mixed>|null $reports
     * @param array<int, string> $pendingReports
     */
    private function processDeliveryReports(mixed $reports, array $pendingReports, int $priorFailed, PushStorage $storage): array
    {
        $sent = 0;
        $failed = $priorFailed;

        if (!is_array($reports)) {
            return ['sent' => $sent, 'failed' => $failed];
        }

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

        return ['sent' => $sent, 'failed' => $failed];
    }

    private function matchesNotificationLevel(mixed $configuredLevel, ?string $requestedPriority): bool
    {
        if ($requestedPriority === null) {
            return true;
        }

        // "very-low" is intentionally a broadcast priority: it should reach every
        // subscriber on the target device, regardless of that subscriber's low/normal/high
        // allowlist settings.
        if ($requestedPriority === 'very-low') {
            return true;
        }

        if ($configuredLevel === null) {
            return true;
        }

        $levels = PushStorage::normalizeNotificationLevels($configuredLevel);

        return $levels[$requestedPriority] ?? false;
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
