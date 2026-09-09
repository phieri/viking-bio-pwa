<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use VikingBioPush\LastContactState;

header('Content-Type: application/json; charset=utf-8');

$state = new LastContactState(__DIR__ . '/../storage/last-contact.json');
echo json_encode($state->summary(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
