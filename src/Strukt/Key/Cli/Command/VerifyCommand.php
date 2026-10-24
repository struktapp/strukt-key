<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\PublicKey;
use Strukt\Ssl\Signer;

/**
 * @command verify
 * @description Verifies a signature against data and a public key.
 * @usage verify <data> <signature> [options]
 *
 * @argument data
 * @description Data that was signed, or a --file path when omitted.
 *
 * @argument signature
 * @description Base64 signature produced by sign.
 *
 * @option file
 * @description Read the data from this file.
 *
 * @option key
 * @required
 * @description Path to the public key (PEM).
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class VerifyCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = $this->text($arguments, $options);
        $valid = Signer::verify(
            $data,
            (string) $arguments['signature'],
            PublicKey::read((string) $options['key']),
        );

        $this->respond('verify', ['valid' => $valid], (bool) $options['json']);

        return $valid ? 0 : 1;
    }
}