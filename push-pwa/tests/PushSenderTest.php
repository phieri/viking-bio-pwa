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
assertTrue($method->invoke($instance, $allowedLowOnly, 'very-low') === true, 'very-low should respect the low allowlist');
assertTrue($method->invoke($instance, $allowedLowOnly, 'normal') === false, 'normal should not be sent without normal permission');

$nullLevels = null;
assertTrue($method->invoke($instance, $nullLevels, 'very-low') === true, 'missing notification levels should default to allowed');

echo "PushSender notification-level checks passed\n";
