<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Hash\Bcrypt;
use Strukt\Key\Cli\Command;

/**
 * @command bcrypt:check
 * @description Checks a password against a stored bcrypt digest.
 * @usage bcrypt:check <password> <hash> [options]
 *
 * @argument password
 * @description Password candidate.
 *
 * @argument hash
 * @description Stored bcrypt digest.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class BcryptCheckCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $valid = (new Bcrypt())->verify((string) $arguments['password'], (string) $arguments['hash']);

        $this->respond('bcrypt:check', ['valid' => $valid], (bool) $options['json']);

        return $valid ? 0 : 1;
    }
}