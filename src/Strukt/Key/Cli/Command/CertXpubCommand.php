<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\Cert;

/**
 * @command cert:xpub
 * @description Extracts the public key embedded in a certificate.
 * @usage cert:xpub <cert> [options]
 *
 * @argument cert
 * @description Path to the certificate PEM.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class CertXpubCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $pem = Cert::withPath((string) $arguments['cert'])->extractPublicKey()->getPem();

        if ($options['json']) {
            echo json_encode(['public_key' => $pem], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        } else {
            echo $pem;
        }

        return 0;
    }
}