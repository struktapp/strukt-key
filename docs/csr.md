# Certificate signing requests

The CSR pipeline lives under `Strukt\Ssl` and `Strukt\Ssl\Csr`. This rebuild
replaces the two anonymous chain classes the legacy facade handed back with one
named object, `Strukt\Ssl\Request`, backed by `Csr\CsrBuilder`,
`Csr\UniqueName`, and the `Csr` value object.

## The subject name — `Strukt\Ssl\Csr\UniqueName`

Distinctive (subject) name for a request. Accepts friendly alias keys and
expands them to the OpenSSL distinguished-name fields. The alias surface is
unchanged from the legacy package.

```php
use Strukt\Ssl\Csr\UniqueName;

$name = new UniqueName([
    'country'  => 'KE',
    'loc'      => 'Nairobi',
    'subLoc'   => 'Nairobi',
    'org'      => 'Strukt',
    'orgUnit'  => 'Platform',
    'common'   => 'strukt.example',
    'email'    => 'ops@strukt.example',
]);

$name->get('common');          // 'strukt.example'
$name->getDetails();           // OpenSSL field names → values
```

Alias → OpenSSL field map:

| Alias | OpenSSL field |
| --- | --- |
| `country` | `countryName` |
| `loc` | `stateOrProvinceName` |
| `subLoc` | `localityName` |
| `org` | `organizationName` |
| `orgUnit` | `organizationalUnitName` |
| `common` | `commonName` |
| `email` | `emailAddress` |

Empty or `null` values are dropped; unknown aliases are ignored.

## Building a raw CSR — `Strukt\Ssl\Csr\CsrBuilder`

Turns a subject and a key pair into an OpenSSL CSR, honouring the pair's
OpenSSL config (bundled `openssl.cnf`, digest).

```php
use Strukt\Ssl\Csr\CsrBuilder;

$builder = new CsrBuilder(new UniqueName(['common' => 'x']), $pair);
$raw = $builder->getCsr();    // OpenSSLCertificateSigningRequest
$csr = $builder->toCsr();     // wrapped in a Csr value object
```

An empty subject throws `InvalidArgumentException: Csr subject details cannot
be empty.`; OpenSSL failures throw `RuntimeException`.

## The value object — `Strukt\Ssl\Csr\Csr`

Wraps a CSR and, once signed, the resulting certificate. Keeps the legacy
surface (`getSubject`, `parse`, `verifyWith`, `sign`) but returns **real**
values and typed OpenSSL objects instead of opaque strings.

```php
use Strukt\Ssl\Csr\Csr;

$csr = Csr::make($rawOrPem);      // factory; accepts OpenSSL CSR or PEM string
$csr->getCsr();                   // PEM request
$csr->getSubject();               // subject fields array
$csr->setCsr($pem);               // store PEM directly

// after signing (see Request::selfSign / Csr::sign):
$csr->getCertPem();               // exported certificate PEM
$csr->exportCert($cert);          // store an OpenSSLCertificate or PEM
$csr->parse();                    // parsed cert fields array|null
$csr->verifyWith($privKey);       // bool — does the stored cert match this key?
```

Static helpers:

```php
use Strukt\Ssl\Csr\Csr;
use Strukt\Ssl\PrivateKey;

Csr::parseCert($certOrPem);                       // ?array of fields
Csr::verifyCert(PrivateKey::read($keyPath), $cert); // bool — cert matches key?

$cert = Csr::sign($csr, PrivateKey::read($caKey), 365);   // CA-signed cert
```

`Csr::sign(Csr $request, PrivateKey $privKey, int $days = 365, int $serial =
0)` — `self::sign` with `null` CA certificate (so it self-signs with `$privKey`,
the CA key). The certificate is also stored back on `$request` via
`exportCert()`.

## The pipeline — `Strukt\Ssl\Request`

One object serves both flows:

```text
->useCsr($names)   send the CSR to a CA and later sign() it
->withCert($path)  adopt on-disk certificate material and verify it
```

```php
use Strukt\Ssl\Request;

$request = new Request($pair, new UniqueName(['common' => 'strukt.example']));

$request->getCsr();       // Csr value object (the request material)
$request->selfSign(365);  // sign with the pair's own private key; returns $this

$request->getXCert();     // OpenSSLCertificate produced by selfSign(), if any
$request->getCert();      // PEM of the current certificate
$request->verify();       // bool — cert belongs to the pair's private key
```

### CA flow

Sign someone else's request with the pair's private key as the CA:

```php
$request = new Request($pair, new UniqueName(['common' => 'client.example']));
$cert = $request->sign(365, 42);   // serial 42; OpenSSL default when 0
```

### Verifying and adopting on-disk material

```php
$request->verify();                                   // stored cert vs pair key
$request->verify($certOrPem);                         // vs explicit material
$request->importCert('client/cert.pem');              // adopt a file; returns $this
```

`verify()` with no certificate stored throws `RuntimeException: No certificate
to verify.`. `importCert()` validates the path with `Fs::isPath`.

## Constructor

`new Request(KeyPairInterface $keys, UniqueName $names, ?Config $config =
null)` — builds the CSR eagerly in the constructor from the subject and the
pair's private key.

## Facade shortcuts

`Strukt\Ssl\All` exposes the same flow without building a `Request` by hand —
`useCsr($names)` and `withCert($path, $names)`; see [facade.md](facade.md).