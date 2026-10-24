<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\Cert;

/**
 * @command cert:info
 * @description Reads the interesting fields out of a certificate.
 * @usage cert:info <cert> [options]
 *
 * @argument cert
 * @description Path to the certificate PEM.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class CertInfoCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $parser = Cert::withPath((string) $arguments['cert'])->parser();

        $this->respond('cert:info', [
            'subject' => (string) ($parser->getDomain() ?? ''),
            'issuer' => (string) ($parser->getIssuer() ?? ''),
            'signature_algo' => (string) ($parser->getSignatureAlgo() ?? ''),
            'valid_from' => $parser->getFromDate()->format('Y-m-d H:i:s'),
            'valid_to' => $parser->getToDate()->format('Y-m-d H:i:s'),
            'expired' => $parser->isExpired(),
            'self_signed' => $parser->isSelfSigned(),
            'fingerprint' => $parser->getFingerPrint(),
        ], (bool) $options['json']);

        return 0;
    }
}