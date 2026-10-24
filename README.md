Strukt Key
===

Cryptography, signing, and SSL utilities for PHP 8.2+, built on the
[Strukt Math](../math), [Strukt Console](../console), and
[Strukt Fs](../fs) components.

No external crypto services, HTTP calls, or bundled private keys are required.
Keys are generated in memory and written only where you ask; tests never touch
committed key material.

## Install

```bash
composer require strukt/key
```

The package installs a CLI executable:

```bash
vendor/bin/kcli --help
```

## Commands

```text
hash            Compute a message digest
bcrypt          Hash a password with bcrypt
bcrypt:check    Check a password against a bcrypt digest
keys:new        Generate an RSA key pair on disk
enc/dec         AES encrypt / decrypt
sign/verify     Sign / verify data with an RSA key
cert:selfsign   Generate a key pair and self-signed certificate
cert:verify     Verify a certificate (optionally against a private key)
cert:xpub       Extract the public key from a certificate
cert:info       Read the fields of a certificate
jwt:encode      Mint a JSON web token
jwt:decode      Decode and validate a JSON web token
envelope:close  Seal a message for a set of recipients
envelope:open   Open a sealed message with a private key
csrf            Mint a CSRF token
csrf:check      Validate a CSRF token
```

Every command supports `--json` where applicable.

## Examples

```bash
./vendor/bin/kcli hash "hello world"
./vendor/bin/kcli bcrypt "s3cret!" --cost=12
./vendor/bin/kcli bcrypt:check "s3cret!" '$2y$12$...'

# RSA keys + sign/verify
./vendor/bin/kcli keys:new --dir keys --name alice
./vendor/bin/kcli sign "the document" --key keys/alice.pem
./vendor/bin/kcli verify "the document" "$SIG" --key keys/alice.pub.pem

# AES with an auto-generated IV carried in the output
./vendor/bin/kcli enc "top secret" "a-strong-key" --json
./vendor/bin/kcli dec "$CIPHERTEXT" "a-strong-key"

# Certificates
./vendor/bin/kcli cert:selfsign --dir keys --name web --common strukt.example --days 365
./vendor/bin/kcli cert:info keys/cert.pem
./vendor/bin/kcli cert:xpub keys/cert.pem --json

# JWTs and CSRF
./vendor/bin/kcli jwt:encode '{"role":"admin"}' "jwt-secret"
./vendor/bin/kcli jwt:decode "$TOKEN" "jwt-secret"
./vendor/bin/kcli csrf '{"user":42}' "csrf-key"
./vendor/bin/kcli csrf:check "$TOKEN" "csrf-key"

# Envelopes (multi-recipient sealing, comma-separated certificate paths)
./vendor/bin/kcli envelope:close "letter" "ca.pem,another.pem" --json
./vendor/bin/kcli envelope:open "$ENV_KEY" "$SEALED" "$IV" --key alice.pem
```

Input can be piped in, or read from a file with `--file`:

```bash
cat message.txt | vendor/bin/kcli hash
./vendor/bin/kcli enc --file document.txt "a-strong-key"
```

## PHP API

Hashing:

```php
use Strukt\Hash\Bcrypt;
use Strukt\Hash\Sha;

$hash = (new Bcrypt())->makeHash('p@55w0rd');
(new Bcrypt())->verify('p@55w0rd', $hash); // true

Sha::once256('abc');
Sha::dbl256('abc');
Sha::hmac('key', 'data', 'sha256'); // raw binary
```

Symmetric AES with an auto-generated IV:

```php
use Strukt\Codec;

$codec = Codec::make('a-strong-key');            // random IV per message
$wrapped = $codec->encode($plain);               // "iv-hex:base64"
$codec->decode($wrapped);                        // back to plain text
```

JWTs (self-contained, HS256/384/512):

```php
use Strukt\Jwt;

$signer = Jwt::make(['secret' => 'jwt-secret', 'algo' => 'HS256', 'expire' => 3600]);

$token = $signer->encode(['role' => 'admin']);
$claims = $signer->decode($token);               // stdClass|null on failure
$signer->valid($token);                          // true
```

CSRF:

```php
use Strukt\Csrf;

$token = Csrf::make(['user' => 42], 'csrf-key', 300)->encode();
Csrf::valid($token, 'csrf-key');                 // true
```

Key pairs, signing, ciphering:

```php
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\Cipher;
use Strukt\Ssl\Signer;
use Strukt\Ssl\KeyPairBuilder;

$pair = KeyPairBuilder::make('keys/', 'alice')->makeKeyPair();
$pair->makePrivateKeyFile();
$pair->makePublicKeyFile();

$signer = new Signer($pair);
$signature = $signer->create('the document');
$signer->check('the document', $signature);      // true

$cipher = new Cipher($pair);
$cipher->decrypt($cipher->encrypt('classified')); // 'classified'
```

Envelopes and recipient lists:

```php
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PublicKeyList;

[$envKeys, $sealed, $iv] = Envelope::withAlgo()->useCerts([$certPath])->closeWithIv($message);

Envelope::withAlgo($iv)->usePrivKey($privateKey)->open($envKeys[0], $sealed);
```

Certificates and CSRs:

```php
use Strukt\Ssl\Cert;
use Strukt\Ssl\Request;
use Strukt\Ssl\Certificate\Parser;
use Strukt\Ssl\Csr\UniqueName;

$request = new Request($pair, new UniqueName(['common' => 'strukt.example']));
$request->selfSign(365);                          // returns $this with a cert
$request->verify();                               // cert belongs to the pair

$parser = new Parser($pem);                       // or Cert::withPath()->parser()
$parser->getDomain();
$parser->getIssuer();
$parser->isExpired();                             // real bool, not a string
```

The facade keeps the legacy entry points:

```php
use Strukt\Ssl\All;

$tool = All::makeKeys();                          // fresh in-memory pair
$tool = All::keyPath('keys/alice.pem');           // adopt an existing key
$tool->toSend($message);                          // encrypt for the pair's public half
$tool->useCsr(['common' => 'x'])->selfSign();
```

### Global helpers

Registered through the Strukt base helper registry, usable from anywhere the
vendor autoload is loaded:

```text
codec($key, $cipher, $vector?)       Codec
bcry($password, $cost?)              object with encode()/verify()
sha256($input)                       hex digest
sha256dbl($input)                    double hex digest
csrf($data, $key, $ttl?)             object with encode()/decode()/valid()
jwt($data, $secret, $algo?, $ttl?)   token string, or object with valid()/yield()
ssl($arg?)                           All facade
keypair($privateKeyPath?)            KeyPair
pubkey($path)                        PublicKey
```

Unlike the legacy package, secrets are always explicit parameters — never
pulled from a global config file.

## Design

The rebuild keeps the drop-in `Strukt\` namespace and class surface of
`strukt1/strukt-key`, then removes the rough edges:

- `Bcrypt` delegates to native `password_hash()`/`password_verify()` with a
  CSPRNG salt, instead of the hand-rolled `crypt()` salts of the original.
- `Jwt` is self-contained (`hash_hmac` + `hash_equals`), dropping the
  `firebase/php-jwt` dependency.
- `Codec` generates a fresh random IV per message by default and carries it in
  the output, so one key can be reused safely.
- The certificate parser returns booleans and `DateTime` values instead of
  `"true"`/`"false"` strings.
- OpenSSL objects are typed (`OpenSSLAsymmetricKey`, `OpenSSLCertificate`,
  `OpenSSLCertificateSigningRequest`); errors surface as exceptions, not
  silent `false`.
- Anonymous chain classes became the named `Request` and `Envelope\Pockets`
  value objects.
- Helpers take explicit arguments; generation defaults are sensible
  (2048-bit RSA, bundled `asset/openssl.cnf`); tests generate ephemeral keys.

## Tests

```bash
composer test
composer lint
```

## License

MIT.