<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Jwt;

/**
 * @command jwt:encode
 * @description Mints a JSON web token.
 * @usage jwt:encode <data> <secret> [options]
 *
 * @argument data
 * @description JSON payload embedded in the token.
 *
 * @argument secret
 * @description Signing key.
 *
 * @option algo
 * @default HS256
 * @enum HS256,HS384,HS512
 * @description Signature algorithm.
 *
 * @option ttl
 * @type integer
 * @default 3600
 * @description Validity in seconds.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class JwtEncodeCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $payload = json_decode((string) $arguments['data'], true);

        if (!is_array($payload)) {
            throw new \InvalidArgumentException('Data is not valid JSON.');
        }

        $token = Jwt::make([
            'secret' => $this->secret($arguments, $options),
            'algo' => (string) $options['algo'],
            'expire' => (int) $options['ttl'],
        ])->encode($payload);

        $this->respond('jwt:encode', ['token' => $token], (bool) $options['json']);

        return 0;
    }
}