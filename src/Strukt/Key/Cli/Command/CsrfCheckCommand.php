<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Csrf;
use Strukt\Key\Cli\Command;

/**
 * @command csrf:check
 * @description Checks a CSRF token against a key.
 * @usage csrf:check <token> <secret> [options]
 *
 * @argument token
 * @description Token to validate.
 *
 * @argument secret
 * @description Symmetric key.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class CsrfCheckCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $valid = Csrf::valid((string) $arguments['token'], $this->secret($arguments, $options));

        $this->respond('csrf:check', ['valid' => $valid], (bool) $options['json']);

        return $valid ? 0 : 1;
    }
}