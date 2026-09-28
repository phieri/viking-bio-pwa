<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/PushStorage.php';
require dirname(__DIR__) . '/src/PushSender.php';

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$method = new \ReflectionMethod(VikingBioPush\PushSender::class, 'matchesNotificationLevel');
$method->setAccessible(true);
$instance = (new \ReflectionClass(VikingBioPush\PushSender::class))->newInstanceWithoutConstructor();

$allowedLowOnly = ['low' => true, 'normal' => false, 'high' => false];
assertTrue($method->invoke($instance, $allowedLowOnly, 'very-low') === true, 'very-low should be intentionally broadcast to all subscribers');
assertTrue($method->invoke($instance, $allowedLowOnly, 'normal') === false, 'normal should still respect the subscriber allowlist');

$nullLevels = null;
assertTrue($method->invoke($instance, $nullLevels, 'very-low') === true, 'missing notification levels should still allow a very-low broadcast');

assertTrue(VikingBioPush\PushSender::normalizeUiTargetUrl('//evil.example', 'https://ui.example') === 'https://ui.example', 'protocol-relative links must not be treated as same-origin UI targets');
assertTrue(VikingBioPush\PushSender::normalizeUiTargetUrl('/status?device=a', 'https://ui.example') === '/status?device=a', 'same-origin relative links should be kept as-is');
assertTrue(VikingBioPush\PushSender::normalizeUiTargetUrl('https://ui.example/status', 'https://ui.example') === 'https://ui.example/status', 'same-host absolute URLs should be accepted');

$payloadMethod = new \ReflectionMethod(VikingBioPush\PushSender::class, 'buildPayload');
$payloadMethod->setAccessible(true);
$jsonErrorThrown = false;
try {
    $payloadMethod->invoke($instance, "\xFF", 'body', null, []);
} catch (JsonException) {
    $jsonErrorThrown = true;
}
assertTrue($jsonErrorThrown, 'invalid UTF-8 payloads should fail with a JSON exception');

$subscriptionPath = __DIR__ . '/.subscriptions-' . bin2hex(random_bytes(6)) . '.yaml';
try {
    $storage = new VikingBioPush\PushStorage($subscriptionPath);
    $endpoint = 'https://push.example/subscriber?name=quoted"device';
    file_put_contents($subscriptionPath, "subscriptions:\n"
        . '  - endpoint: ' . json_encode($endpoint, JSON_UNESCAPED_SLASHES) . "\n"
        . "    keys:\n"
        . "      p256dh: \"public-key\"\n"
        . "      auth: \"auth-key\"\n"
        . "    sender: \"viking-bio-01\"\n"
        . "    language: \"en\"\n"
        . "    notificationLevel:\n"
        . "      low: true\n"
        . "      normal: true\n"
        . "      high: false\n"
        . "    uiUrl: \"https://ui.example\"\n");
    $subscriptions = $storage->all();
    assertTrue(count($subscriptions) === 1, 'manually pasted YAML snippet should produce one subscription');
    assertTrue($subscriptions[0]['endpoint'] === $endpoint, 'JSON-quoted YAML scalar should preserve punctuation');
    assertTrue($subscriptions[0]['keys']['auth'] === 'auth-key', 'manual YAML should preserve subscription keys');
    assertTrue($subscriptions[0]['notificationLevel']['high'] === false, 'manual YAML should preserve notification levels');
} finally {
    if (is_file($subscriptionPath)) {
        unlink($subscriptionPath);
    }
}

echo "PushSender validation checks passed\n";
