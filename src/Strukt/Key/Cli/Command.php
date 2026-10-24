<?php

declare(strict_types=1);

namespace Strukt\Key\Cli;

/**
 * Shared behavior for every key command.
 *
 * Concrete commands carry their own PHPDoc description and delegate the heavy
 * lifting to the toolbox, while this base resolves input from an argument, a
 * file option, or standard input, and renders the result as JSON or as a
 * short plain text report.
 */
abstract class Command
{
    /**
     * Resolves text input from a file option, the data argument, or standard
     * input when both are absent.
     *
     * @param array<string, mixed> $arguments Positional arguments.
     * @param array<string, mixed> $options Options.
     * @return string Input data.
     */
    protected function text(array $arguments, array $options): string
    {
        if (($options['file'] ?? null) !== null) {
            return $this->read((string) $options['file']);
        }

        if (($arguments['data'] ?? null) !== null) {
            return (string) $arguments['data'];
        }

        return trim((string) stream_get_contents(STDIN));
    }

    /**
     * Resolves a symmetric secret from a trickle of candidate spots.
     *
     * @param array<string, mixed> $arguments Positional arguments.
     * @param array<string, mixed> $options Options.
     * @return string Secret.
     * @throws \InvalidArgumentException When no secret can be found.
     */
    protected function secret(array $arguments, array $options): string
    {
        $secret = $options['secret'] ?? $arguments['secret'] ?? null;

        if ($secret === null) {
            throw new \InvalidArgumentException('A secret is required, pass --secret=<value>.');
        }

        return (string) $secret;
    }

    /**
     * Reads a file as text.
     *
     * @return string File contents.
     */
    protected function read(string $path): string
    {
        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw new \RuntimeException(sprintf('Unable to read file [%s].', $path));
        }

        return $contents;
    }

    /**
     * Prints a result either as JSON or as a short plain text report.
     *
     * @param string $command Command name, shown in the report header.
     * @param array<string, mixed> $result Command result.
     * @param bool $json Whether to render as JSON.
     */
    protected function respond(string $command, array $result, bool $json): void
    {
        echo $json
            ? json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL
            : $this->format($command, $result);
    }

    /**
     * Renders a result as a short plain text report.
     *
     * @param string $command Command name, shown in the header.
     * @param array<string, mixed> $result Command result.
     * @return string Report text.
     */
    private function format(string $command, array $result): string
    {
        $report = "Strukt Key — $command\n──────────────────────\n";

        foreach ($result as $key => $value) {
            if (is_array($value)) {
                $report .= "$key:\n";

                foreach ($value as $nested => $nestedValue) {
                    $report .= '  ' . $nested . ': '
                        . (is_array($nestedValue) ? json_encode($nestedValue) : $this->render($nestedValue)) . "\n";
                }

                continue;
            }

            $report .= str_replace('_', ' ', $key) . ': ' . $this->render($value) . "\n";
        }

        return $report;
    }

    /**
     * Renders one scalar value for the report.
     */
    private function render(mixed $value): string
    {
        return match (true) {
            is_bool($value) => $value ? 'true' : 'false',
            $value === null => '',
            default => (string) $value,
        };
    }
}