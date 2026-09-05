<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\VapidConfig;

header('Content-Type: application/json; charset=utf-8');

$config = new VapidConfig(__DIR__ . '/../storage/vapid.json');

echo json_encode(['publicKey' => $config->publicKey()], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
