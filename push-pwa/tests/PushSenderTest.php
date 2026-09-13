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

echo "PushSender validation checks passed\n";
