<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Csrf;
use Strukt\Key\Cli\Command;

/**
 * @command csrf
 * @description Mints a cross-site request forgery token.
 * @usage csrf <data> <secret> [options]
 *
 * @argument data
 * @description Payload embedded in the token, JSON when it is an object.
 *
 * @argument secret
 * @description Symmetric key.
 *
 * @option ttl
 * @type integer
 * @default 300
 * @description Seconds the token stays valid.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class CsrfCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = json_decode((string) $arguments['data'], true) ?? $arguments['data'];

        $token = Csrf::make($data, $this->secret($arguments, $options), (int) $options['ttl'])->encode();

        $this->respond('csrf', ['token' => $token], (bool) $options['json']);

        return 0;
    }
}