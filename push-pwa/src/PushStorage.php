<?php

declare(strict_types=1);

namespace VikingBioPush;

final class PushStorage
{
    public function __construct(private readonly string $path)
    {
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        if (!is_file($this->path)) {
            return [];
        }

        $contents = file_get_contents($this->path);
        if ($contents === false || trim($contents) === '') {
            return [];
        }

        $data = json_decode($contents, true);
        if (!is_array($data)) {
            return [];
        }

        return array_values(array_filter($data, static fn ($row) => is_array($row)));
    }

}
