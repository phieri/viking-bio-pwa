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

            $contents = self::yamlEncode($scaffold) . "\n";
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

        $decoded = self::decode($contents);
        if (!is_array($decoded)) {
            return [];
        }

        return array_values(array_filter($decoded, static fn ($row) => is_array($row)));
    }

    /**
     * @param array<int, array<string, mixed>> $subscriptions
     */
    private static function yamlEncode(array $subscriptions): string
    {
        $lines = [];
        foreach ($subscriptions as $subscription) {
            if (!is_array($subscription)) {
                continue;
            }

            $lines[] = '- endpoint: ' . self::yamlString((string) ($subscription['endpoint'] ?? ''));

            $keys = $subscription['keys'] ?? [];
            if (is_array($keys) && $keys !== []) {
                $lines[] = '  keys:';
                foreach ($keys as $key => $value) {
                    $lines[] = '    ' . self::yamlKey((string) $key) . ': ' . self::yamlString((string) $value);
                }
            }

            foreach ($subscription as $key => $value) {
                if ($key === 'endpoint' || $key === 'keys') {
                    continue;
                }

                $lines[] = '  ' . self::yamlKey((string) $key) . ': ' . self::yamlString((string) $value);
            }
        }

        return implode("\n", $lines);
    }

    private static function yamlString(string $value): string
    {
        try {
            return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $exception) {
            throw new \RuntimeException('Unable to encode subscription value as YAML-safe JSON: ' . $exception->getMessage(), 0, $exception);
        }
    }

    private static function yamlKey(string $key): string
    {
        if (preg_match('/^[A-Za-z0-9_-]+$/', $key) !== 1) {
            throw new \InvalidArgumentException('Subscription keys must use only letters, numbers, underscores, and dashes');
        }

        return $key;
    }

    /**
     * @return array<int, array<string, mixed>>|null
     */
    private static function decode(string $contents): ?array
    {
        $trimmed = trim($contents);
        if ($trimmed === '') {
            return [];
        }

        $json = json_decode($trimmed, true);
        if (is_array($json)) {
            return $json;
        }

        $yaml = self::parseSimpleYaml($trimmed);
        if (is_array($yaml)) {
            return $yaml;
        }

        return null;
    }

    /**
     * @return array<int, array<string, mixed>>|null
     */
    private static function parseSimpleYaml(string $contents): ?array
    {
        $lines = preg_split('/\R/', $contents);
        if ($lines === false || $lines === []) {
            return null;
        }

        $items = [];
        $current = null;
        $nestedKey = null;
        $nestedIndent = 0;

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }

            $indent = strlen($line) - strlen(ltrim($line, " \t"));
            if ($nestedKey !== null && $indent > $nestedIndent && preg_match('/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/', $trimmed, $matches) === 1) {
                if (!isset($current[$nestedKey]) || !is_array($current[$nestedKey])) {
                    $current[$nestedKey] = [];
                }
                $current[$nestedKey][$matches[1]] = self::yamlScalar($matches[2]);
                continue;
            }

            $nestedKey = null;
            $nestedIndent = 0;

            if (preg_match('/^-\s*(.*)$/', $trimmed, $matches) === 1) {
                if ($current !== null) {
                    $items[] = $current;
                }
                $current = [];
                $remainder = trim($matches[1]);
                if ($remainder !== '') {
                    if (preg_match('/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/', $remainder, $kv) === 1) {
                        $current[$kv[1]] = self::yamlScalar($kv[2]);
                    }
                }
                continue;
            }

            if ($current === null) {
                continue;
            }

            if (preg_match('/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/', $trimmed, $matches) === 1) {
                $key = $matches[1];
                $value = trim($matches[2]);
                if ($value === '') {
                    $current[$key] = [];
                    $nestedKey = $key;
                    $nestedIndent = $indent;
                    continue;
                }

                $current[$key] = self::yamlScalar($value);
            }
        }

        if ($current !== null) {
            $items[] = $current;
        }

        return $items;
    }

    private static function yamlScalar(string $value): mixed
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }

        if (str_starts_with($value, '"') && str_ends_with($value, '"')) {
            return self::yamlUnescape(substr($value, 1, -1));
        }

        if (str_starts_with($value, "'") && str_ends_with($value, "'")) {
            return str_replace("''", "'", substr($value, 1, -1));
        }

        if (strtolower($value) === 'true') {
            return true;
        }

        if (strtolower($value) === 'false') {
            return false;
        }

        if (strtolower($value) === 'null') {
            return null;
        }

        if (is_numeric($value)) {
            return 0 + $value;
        }

        return $value;
    }

    private static function yamlUnescape(string $value): string
    {
        $decoded = '';
        $length = strlen($value);

        for ($index = 0; $index < $length; $index++) {
            $character = $value[$index];
            if ($character !== '\\' || $index + 1 >= $length) {
                $decoded .= $character;
                continue;
            }

            $next = $value[$index + 1];
            $index++;

            switch ($next) {
                case '"':
                    $decoded .= '"';
                    break;
                case '\\':
                    $decoded .= '\\';
                    break;
                case 'n':
                    $decoded .= "\n";
                    break;
                case 'r':
                    $decoded .= "\r";
                    break;
                case 't':
                    $decoded .= "\t";
                    break;
                case 'u':
                    $hex = substr($value, $index + 1, 4);
                    if (preg_match('/^[0-9A-Fa-f]{4}$/', $hex) === 1) {
                        $codePoint = hexdec($hex);
                        if ($codePoint <= 0x7F) {
                            $decoded .= chr($codePoint);
                        } elseif ($codePoint <= 0x7FF) {
                            $decoded .= chr(0xC0 | ($codePoint >> 6)) . chr(0x80 | ($codePoint & 0x3F));
                        } else {
                            $decoded .= chr(0xE0 | ($codePoint >> 12)) . chr(0x80 | (($codePoint >> 6) & 0x3F)) . chr(0x80 | ($codePoint & 0x3F));
                        }
                        $index += 4;
                        break;
                    }
                    $decoded .= 'u';
                    break;
                case 'x':
                    $hex = substr($value, $index + 1, 2);
                    if (preg_match('/^[0-9A-Fa-f]{2}$/', $hex) === 1) {
                        $decoded .= chr(hexdec($hex));
                        $index += 2;
                        break;
                    }
                    $decoded .= 'x';
                    break;
                default:
                    $decoded .= $next;
                    break;
            }
        }

        return $decoded;
    }
}
