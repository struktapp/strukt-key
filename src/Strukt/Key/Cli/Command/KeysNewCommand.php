<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\KeyPairBuilder;

/**
 * @command keys:new
 * @description Generates an RSA key pair on disk.
 * @usage keys:new [options]
 *
 * @option dir
 * @default keys/
 * @description Directory the key files are written to.
 *
 * @option name
 * @default key
 * @description Base file name without an extension.
 *
 * @option bits
 * @type integer
 * @default 2048
 * @description RSA modulus size.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class KeysNewCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $pair = KeyPairBuilder::make()
            ->setDirectory((string) $options['dir'])
            ->setName((string) $options['name'])
            ->setConfigOptions(['private_key_bits' => (int) $options['bits']])
            ->makeKeyPair();

        $private = $pair->makePrivateKeyFile();
        $public = $pair->makePublicKeyFile();

        $this->respond('keys:new', [
            'private' => $private,
            'public' => $public,
            'bits' => (int) $options['bits'],
        ], (bool) $options['json']);

        return 0;
    }
}