<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\Envelope;

/**
 * @command envelope:close
 * @description Seals a message for a set of recipients.
 * @usage envelope:close <data> <recipients> [options]
 *
 * @argument data
 * @description Message to seal, or a --file path when omitted.
 *
 * @argument recipients
 * @description Comma-separated paths to recipient certificate PEMs. Each gets
 *              its own envelope key.
 *
 * @option file
 * @description Read the message from this file.
 *
 * @option cipher
 * @default AES-128-CBC
 * @description Symmetric cipher used for the payload.
 *
 * @option iv
 * @description Fixed hex IV. A random IV is generated and reported when empty.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class EnvelopeCloseCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = $this->text($arguments, $options);
        $recipients = array_filter(array_map('trim', explode(',', (string) $arguments['recipients'])));

        if ($recipients === []) {
            throw new \InvalidArgumentException('At least one recipient certificate is required.');
        }

        $envelope = Envelope::withAlgo(($options['iv'] ?? null) !== null && ($options['iv'] ?? '') !== '' ? hex2bin((string) $options['iv']) : null, (string) $options['cipher']);

        [$envKeys, $sealed, $iv] = $envelope->useCerts($recipients)->closeWithIv($data);

        $this->respond('envelope:close', [
            'envelope_keys' => $envKeys,
            'sealed' => $sealed,
            'iv' => bin2hex($iv),
        ], (bool) $options['json']);

        return 0;
    }
}