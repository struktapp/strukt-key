<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Codec;
use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;

/**
 * @command enc
 * @description Encrypts data with AES.
 * @usage enc <data> <secret> [options]
 *
 * @argument data
 * @description Plain text, or a --file path when omitted.
 *
 * @argument secret
 * @description Symmetric key.
 *
 * @option file
 * @description Read the data from this file.
 *
 * @option cipher
 * @default AES-128-CBC
 * @description Cipher name.
 *
 * @option vector
 * @description Fixed hex IV. When absent a random IV is generated and carried
 *              in the result as iv.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class EncCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = $this->text($arguments, $options);
        $secret = $this->secret($arguments, $options);
        $randomVector = ($options['vector'] ?? null) === null;

        $codec = Codec::make($secret, (string) $options['cipher'], $options['vector'] ?? null);
        $cipherText = $codec->encode($data);

        $result = ['cipher' => (string) $options['cipher'], 'ciphertext' => $cipherText];

        if ($randomVector) {
            $result['iv'] = explode(':', $cipherText, 2)[0];
        }

        $this->respond('enc', $result, (bool) $options['json']);

        return 0;
    }
}