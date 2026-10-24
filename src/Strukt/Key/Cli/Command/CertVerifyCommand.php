<?php

declare(strict_types=1);

namespace Strukt\Key\Cli\Command;

use Strukt\Console\Runtime\CommandInterface;
use Strukt\Key\Cli\Command;
use Strukt\Ssl\Cert;
use Strukt\Ssl\PrivateKey;

/**
 * @command cert:verify
 * @description Verifies a certificate, optionally against a private key.
 * @usage cert:verify <cert> [options]
 *
 * @argument cert
 * @description Path to the certificate PEM.
 *
 * @option key
 * @description Path to a private key to match against the certificate.
 *
 * @option json
 * @flag
 * @description Render the result as JSON.
 */
class CertVerifyCommand extends Command implements CommandInterface
{
    public function execute(array $arguments, array $options): int
    {
        $certPath = (string) $arguments['cert'];

        if (!is_file($certPath)) {
            throw new \RuntimeException(sprintf('Certificate file [%s] not found.', $certPath));
        }

        $parser = Cert::withPath($certPath)->parser();

        $result = [
            'valid' => true,
            'expired' => $parser->isExpired(),
            'subject' => $parser->getDomain(),
            'issuer' => $parser->getIssuer(),
        ];

        if (($options['key'] ?? null) !== null) {
            $result['valid'] = \Strukt\Ssl\Csr\Csr::verifyCert(PrivateKey::read((string) $options['key']), $this->read($certPath));
        }

        $this->respond('cert:verify', $result, (bool) $options['json']);

        return $result['valid'] && !$parser->isExpired() ? 0 : 1;
    }
}