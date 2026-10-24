<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Request;

/**
 * @command cert:selfsign
 * @description Generates a key pair and a self-signed certificate.
 * @usage cert:selfsign [options]
 *
 * @option dir
 * @default keys/
 * @description Directory the key and certificate files are written to.
 *
 * @option name
 * @default key
 * @description Base file name for the key pair.
 *
 * @option days
 * @type integer
 * @default 365
 * @description Certificate lifetime.
 *
 * @option cert
 * @default cert.pem
 * @description Certificate file name written to the directory.
 *
 * @option common
 * @default localhost
 * @description Subject common name.
 *
 * @option org
 * @description Subject organization name.
 *
 * @option orgUnit
 * @description Subject organizational unit name.
 *
 * @option email
 * @description Subject email address.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class CertSelfsignCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $dir = (string) $options['dir'];
        $name = (string) $options['name'];
        $pair = KeyPairBuilder::make($dir, $name)->makeKeyPair();

        $names = array_filter([
            'common' => $options['common'] ?? null,
            'org' => $options['org'] ?? null,
            'orgUnit' => $options['orgUnit'] ?? null,
            'email' => $options['email'] ?? null,
        ], static fn ($value) => $value !== null);

        $request = new Request($pair, new \Strukt\Ssl\Csr\UniqueName($names));
        $request->selfSign((int) $options['days']);

        $pair->makePrivateKeyFile();
        $pair->makePublicKeyFile();

        $certPath = $dir . '/' . $options['cert'];

        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Unable to create directory [%s].', $dir));
        }

        file_put_contents($certPath, $request->getCert());

        $this->respond('cert:selfsign', [
            'private' => $pair->privateKeyFile(),
            'public' => $pair->publicKeyFile(),
            'cert' => $certPath,
            'subject' => $request->getCsr()->getSubject(),
        ], (bool) $options['json']);

        return 0;
    }
}