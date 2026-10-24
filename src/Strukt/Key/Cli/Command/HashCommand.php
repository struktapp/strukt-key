<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Hash\Sha;
use Strukt\Key\Cli\Command;

/**
 * @command hash
 * @description Computes a message digest of the input.
 * @usage hash <data> [options]
 *
 * @argument data
 * @description Data to hash, or a --file path when omitted.
 *
 * @option file
 * @description Read the data from this file.
 *
 * @option type
 * @default sha256
 * @enum sha256,sha512,sha1,md5,sha256dbl
 * @description Hash algorithm; sha256dbl applies the digest twice.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class HashCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = $this->text($arguments, $options);
        $type = (string) $options['type'];

        $digest = $type === 'sha256dbl'
            ? Sha::dbl256($data)
            : Sha::once($data, $type);

        $this->respond('hash', ['type' => $type, 'hash' => $digest], (bool) $options['json']);

        return 0;
    }
}