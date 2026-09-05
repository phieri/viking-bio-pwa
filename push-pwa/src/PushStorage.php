<?php

declare(strict_types=1);

namespace VikingBioPush;

final class PushStorage
{
    public function __construct(private readonly string $path)
    {
        $directory = dirname($this->path);
        if ($directory !== '' && !is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        if (is_link($this->path) || (file_exists($this->path) && !is_file($this->path))) {
            throw new \RuntimeException('Subscription storage path must be a regular file');
        }

        if (!is_file($this->path)) {
            $handle = fopen($this->path, 'xb');
            if ($handle === false) {
                throw new \RuntimeException('Unable to create the initial subscription scaffold file');
            }

            $scaffold = [
                [
                    'endpoint' => 'https://example.com/replace-me',
                    'keys' => [
                        'p256dh' => 'replace-with-browser-public-key',
                        'auth' => 'replace-with-browser-auth',
                    ],
                    'priority' => 'normal',
                    'uiUrl' => 'https://example.com/replace-me',
                ],
            ];

            $json = json_encode($scaffold, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if ($json === false) {
                fclose($handle);
                if (is_file($this->path) && unlink($this->path) === false) {
                    throw new \RuntimeException('Unable to encode the initial subscription scaffold; cleanup of the invalid file also failed');
                }
                throw new \RuntimeException('Unable to encode the initial subscription scaffold');
            }

            $contents = $json . "\n";
            $expectedBytes = strlen($contents);
            $written = fwrite($handle, $contents);
            fclose($handle);
            if ($written !== $expectedBytes) {
                if (is_file($this->path) && unlink($this->path) === false) {
                    throw new \RuntimeException('Unable to write the initial subscription scaffold file; cleanup of the partial file also failed');
                }
                throw new \RuntimeException('Unable to write the initial subscription scaffold file');
            }

            if (chmod($this->path, 0600) === false) {
                if (is_file($this->path) && unlink($this->path) === false) {
                    throw new \RuntimeException('Unable to secure the initial subscription scaffold file permissions; cleanup of the partially-created file also failed');
                }
                throw new \RuntimeException('Unable to secure the initial subscription scaffold file permissions');
            }
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
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
