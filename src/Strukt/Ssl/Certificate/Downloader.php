<?php

declare(strict_types=1);

namespace Strukt\Ssl\Certificate;

use OpenSSLCertificate as SslCert;

/**
 * Pulls the TLS certificate a host serves over the wire.
 *
 * Opens a raw TLS socket to `host:port` and grabs the peer certificate from
 * the stream context. Nothing is verified here — this is retrieval, not a
 * trust decision — but the material is typed as a usable certificate object.
 */
final class Downloader
{
    /**
     * Fetches the single peer certificate.
     *
     * @param string $host Target host.
     * @param int $port TLS port, 443 unless told otherwise.
     * @param int $timeout Connection timeout in seconds.
     * @return SslCert Peer certificate.
     * @throws \RuntimeException When the handshake or capture fails.
     */
    public static function single(string $host, int $port = 443, int $timeout = 10): SslCert
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $stream = @stream_socket_client(
            sprintf('tls://%s:%d', $host, $port),
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($stream === false) {
            throw new \RuntimeException(sprintf('Unable to connect to [%s:%d] [%s].', $host, $port, $errstr));
        }

        $params = stream_context_get_params($stream);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        @fclose($stream);

        if (!$cert instanceof SslCert) {
            throw new \RuntimeException(sprintf('Peer certificate for [%s:%d] could not be captured.', $host, $port));
        }

        return $cert;
    }
}