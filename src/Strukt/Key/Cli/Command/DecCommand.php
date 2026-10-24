<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Codec;
use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;

/**
 * @command dec
 * @description Decrypts data produced by enc.
 * @usage dec <data> <secret> [options]
 *
 * @argument data
 * @description Ciphertext, or a --file path when omitted.
 *
 * @argument secret
 * @description Symmetric key.
 *
 * @option file
 * @description Read the ciphertext from this file.
 *
 * @option cipher
 * @default AES-128-CBC
 * @description Cipher name.
 *
 * @option vector
 * @description Fixed hex IV used when the ciphertext carries none.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class DecCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $data = $this->text($arguments, $options);
        $secret = $this->secret($arguments, $options);
        $plain = Codec::make($secret, (string) $options['cipher'], $options['vector'] ?? null)
            ->decode(trim($data));

        $this->respond('dec', ['plain' => $plain], (bool) $options['json']);

        return 0;
    }
}