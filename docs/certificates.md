# Certificates

The certificate surface lives under `Strukt\Ssl`: `Cert` (a file/PEM carrier),
`Certificate\Parser` (field reader), and `Certificate\Downloader` (peer cert
retrieval over the wire).

## Cert — `Strukt\Ssl\Cert`

Loads certificate PEM from a path or string and pulls the public half out of it
— the stepping stone used whenever a certificate must encrypt or verify without
exposing the private side. Uses `Strukt\Fs\Fs` to read files.

```php
use Strukt\Ssl\Cert;

$cert = Cert::withPath('keys/cert.pem');       // file carrier
$cert = Cert::withPem($pem);                   // PEM string carrier

$cert->getResource();                       // OpenSSLAsymmetricKey (public key)
$cert->extractPublicKey();                  // PublicKey wrapper
$cert->parser();                            // Certificate\Parser bound to this cert
```

Missing files throw `InvalidArgumentException: Certificate file [..] not
found.`; unreadable files throw `RuntimeException`.

## Certificate\Parser — `Strukt\Ssl\Certificate\Parser`

Parses certificate material and hands back the interesting parts as **typed
values**. The legacy parser returned `"true"` / `"false"` strings for
booleans; here every answer is a real `bool`, `string`, or `DateTime`.

```php
use Strukt\Ssl\Certificate\Parser;

$parser = new Parser($cert);          // OpenSSLCertificate or PEM string

$parser->getDomain();         // subject CN, e.g. 'strukt.example'
$parser->getIssuer();         // issuer CN
$parser->getSignatureAlgo();  // e.g. 'RSA-SHA256'
$parser->getFromDate();       // DateTime
$parser->getToDate();         // DateTime
$parser->isExpired();         // bool
$parser->isSelfSigned();      // bool — subject CN === issuer CN
$parser->isPreCertificate();  // bool — carries ct_precert_poison extension
$parser->getFingerPrint();    // SHA-1 hex fingerprint
$parser->getPublicKey();      // PublicKey embedded in the certificate
```

### Accessor table

| Method | Returns | Notes |
| --- | --- | --- |
| `getIssuer(): ?string` | issuer common name | `null` when absent |
| `getDomain(): ?string` | subject common name, i.e. the domain | `null` when absent |
| `getSignatureAlgo(): ?string` | signature type SN, e.g. `RSA-SHA256` | `null` when absent |
| `getFromDate(): \DateTime` | validity start | current timezone |
| `getToDate(): \DateTime` | validity end | current timezone |
| `isExpired(): bool` | to-date < now | real bool |
| `isSelfSigned(): bool` | subject CN === issuer CN | real bool |
| `isPreCertificate(): bool` | has `ct_precert_poison` | real bool |
| `getFingerPrint(): string` | SHA-1 fingerprint, hex | computed at construction |
| `getPublicKey(): PublicKey` | embedded public key | throws on failure |

The constructor takes an `OpenSSLCertificate` or PEM string and throws
`RuntimeException: Unable to parse the certificate [..].` when OpenSSL rejects
the input.

## Certificate\Downloader — `Strukt\Ssl\Certificate\Downloader`

Pulls the TLS certificate a host serves over the wire. Opens a raw TLS socket
to `host:port` and grabs the peer certificate out of the stream context.

```php
use Strukt\Ssl\Certificate\Downloader;

$cert = Downloader::single('strukt.example', 443, 10);   // OpenSSLCertificate
```

```php
// chain into the parser for inspection
$info = (new Parser(Downloader::single('github.com')))->getIssuer();
```

`Downloader::single(string $host, int $port = 443, int $timeout = 10)`:
timeout is in seconds. **Nothing is verified here** — this is retrieval, not a
trust decision; the context disables peer verification by design. Failures
throw `RuntimeException` (connection, handshake, or absent peer certificate).

## CLI

The certificate commands live in the [command line docs](cli.md#cert-selfsign):
`cert:selfsign`, `cert:verify`, `cert:xpub`, `cert:info`.