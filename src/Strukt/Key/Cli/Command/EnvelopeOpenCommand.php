<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PrivateKey;

/**
 * @command envelope:open
 * @description Opens a sealed message with the recipient's private key.
 * @usage envelope:open <env-key> <sealed> <iv> [options]
 *
 * @argument env-key
 * @description Base64 envelope key reported by envelope:close for your slot.
 *
 * @argument sealed
 * @description Base64 sealed payload.
 *
 * @argument iv
 * @description Hex IV reported by envelope:close.
 *
 * @option cipher
 * @default AES-128-CBC
 * @description Symmetric cipher the payload was sealed with.
 *
 * @option key
 * @required
 * @description Path to the recipient's private key (PEM).
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class EnvelopeOpenCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $iv = hex2bin((string) $arguments['iv']);

        if ($iv === false) {
            throw new \InvalidArgumentException('IV is not valid hex.');
        }

        $pockets = Envelope::withAlgo($iv, (string) $options['cipher'])
            ->usePrivKey(PrivateKey::read((string) $options['key']));

        $data = $pockets->open((string) $arguments['env-key'], (string) $arguments['sealed']);

        if ($options['json']) {
            echo json_encode(['data' => $data], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        } else {
            echo $data;
        }

        return 0;
    }
}