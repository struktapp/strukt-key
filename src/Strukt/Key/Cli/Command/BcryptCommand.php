<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Hash\Bcrypt;
use Strukt\Key\Cli\Command;

/**
 * @command bcrypt
 * @description Hashes a password with bcrypt.
 * @usage bcrypt <password> [options]
 *
 * @argument password
 * @description Password to hash.
 *
 * @option cost
 * @type integer
 * @default 12
 * @description Bcrypt work factor.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class BcryptCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $cost = (int) $options['cost'];
        $hash = (new Bcrypt($cost))->makeHash((string) $arguments['password']);

        $this->respond('bcrypt', ['cost' => $cost, 'hash' => $hash], (bool) $options['json']);

        return 0;
    }
}