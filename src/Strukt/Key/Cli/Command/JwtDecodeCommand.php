<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Jwt;

/**
 * @command jwt:decode
 * @description Decodes and validates a JSON web token.
 * @usage jwt:decode <token> <secret> [options]
 *
 * @argument token
 * @description Token to inspect.
 *
 * @argument secret
 * @description Signing key.
 *
 * @option algo
 * @default HS256
 * @enum HS256,HS384,HS512
 * @description Signature algorithm the token was minted with.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class JwtDecodeCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $claims = Jwt::make([
            'secret' => $this->secret($arguments, $options),
            'algo' => (string) $options['algo'],
        ])->decode((string) $arguments['token']);

        $result = ['valid' => $claims !== null];

        if ($claims !== null) {
            $result['claims'] = json_decode(json_encode($claims), true);
        }

        $this->respond('jwt:decode', $result, (bool) $options['json']);

        return $claims !== null ? 0 : 1;
    }
}