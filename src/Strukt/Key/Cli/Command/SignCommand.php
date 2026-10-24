<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\PrivateKey;
use Strukt\Ssl\Signer;

/**
 * @command sign
 * @description Signs data with a private key.
 * @usage sign <data> [options]
 *
 * @argument data
 * @description Data to sign, or a --file path when omitted.
 *
 * @option file
 * @description Read the data from this file.
 *
 * @option key
 * @required
 * @description Path to the private key (PEM).
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class SignCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = $this->text($arguments, $options);
        $pair = KeyPair::fromPrivate(PrivateKey::read((string) $options['key']), '.', 'signer');

        $signature = (new Signer($pair))->create($data);

        $this->respond('sign', ['signature' => $signature], (bool) $options['json']);

        return 0;
    }
}