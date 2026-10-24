# Asymmetric encryption and signing

This is the RSA half of the toolbox: key generation and adoption
(`KeyPair`, `KeyPairBuilder`, `PrivateKey`, `PublicKey`, `PublicKeyList`),
asymmetric encryption (`Cipher`), and signatures (`Signer`), under the
`Strukt\Ssl` namespace.

## Key generation defaults — `Strukt\Ssl\Config`

`Config` holds the OpenSSL options passed to key generation. Defaults (see
`Config::dump()`):

| Option | Default |
| --- | --- |
| `config` | bundled `asset/openssl.cnf` |
| `digest_alg` | `sha256` |
| `x509_extensions` | `v3_ca` |
| `req_extensions` | `v3_req` |
| `private_key_bits` | `2048` |
| `private_key_type` | `OPENSSL_KEYTYPE_RSA` |
| `encrypt_key` | `false` |

The defaults mirror the legacy configuration file but move to 2048-bit RSA
(beyond the reach of general attack, fast to generate) and ship a bundled
`openssl.cnf` so generation never depends on the system config being present.

```php
use Strukt\Ssl\Config;

$config = new Config(['private_key_bits' => 4096]);
$config->get('private_key_bits');       // 4096
$config->with('digest_alg', 'sha512');  // returns a copy, original untouched
$bare = Config::dump();                 // the base option set
```

## KeyPair — `Strukt\Ssl\KeyPair`

A key pair bound to a directory and base name. Creation follows two routes:
**generation** (fresh pair in memory, written only when `make*File()` is
called) or **adoption** (`fromPrivate()` — an existing private key backs the
pair and the public half is derived).

### Generate

```php
use Strukt\Ssl\KeyPair;

$pair = KeyPair::make('keys/', 'alice', ['private_key_bits' => 2048]);

$pair->makePrivateKeyFile();    // writes keys/alice.pem
$pair->makePublicKeyFile();     // writes keys/alice.pub.pem
```

File naming is deliberate: the legacy package kept both halves under one
`.pem` path; this rebuild splits them (`<name>.pem` vs `<name>.pub.pem`) so
either file can be handed out independently.

### Adopt an existing private key

```php
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\PrivateKey;

$pair = KeyPair::fromPrivate(PrivateKey::read('keys/alice.pem'), 'keys/', 'alice');
```

`KeyPair::make(string $dir, string $name, array $configOptions = [])` and
`KeyPair::fromPrivate(PrivateKey $private, string $dir, string $name)`.

### KeyPair members

| Member | Meaning |
| --- | --- |
| `privateKeyFile()` / `publicKeyFile()` | concrete file paths |
| `privateKey()` / `publicKey()` | `PrivateKey` / `PublicKey` wrappers |
| `getPrivate()` / `getPublic()` | raw `OpenSSLAsymmetricKey` objects (nullable on the private side) |
| `dir()` / `keyName()` / `config()` | how the pair was bound |
| `makePrivateKeyFile()` / `makePublicKeyFile()` | write the PEMs, creating the directory (mode `0775`) when needed; return the path written |
| `__toString()` | the private key file path |

### The contract

`KeyPair` (and `AbstractKeyPair`) implement `Strukt\Ssl\KeyPairInterface`, the
contract every key carrier upholds: the OpenSSL objects (`getPrivate`,
`getPublic`), the file paths (`privateKeyFile`, `publicKeyFile`), and the
wrappers (`privateKey`, `publicKey`). Certificate and CSR paths therefore never
care whether they hold an on-disk pair or an in-memory one.

## KeyPairBuilder — `Strukt\Ssl\KeyPairBuilder`

Fluent builder used by the CLI and facade.

```php
use Strukt\Ssl\KeyPairBuilder;

$pair = KeyPairBuilder::make('keys/', 'alice')          // optional dir/name
    ->setDirectory('keys/')
    ->setName('alice')
    ->setConfigOptions(['private_key_bits' => 4096])
    ->makeKeyPair();
```

Defaults: `dir = 'keys/'`, `name = 'key'`.

## PrivateKey — `Strukt\Ssl\PrivateKey`

Wrapper over the private half. Loads from a PEM string, a file, or an already
parsed OpenSSL key object, and re-exports itself.

```php
use Strukt\Ssl\PrivateKey;

$key = PrivateKey::read('keys/alice.pem');          // file, 8192-byte cap
$key = PrivateKey::make($pem);                      // from a PEM string
$key = PrivateKey::fromKey($resource);              // from an OpenSSLAsymmetricKey

$key->get();             // OpenSSLAsymmetricKey
$key->getKey();          // legacy alias of get()
$key->getPublicKey();    // PublicKey derived from this private half
$key->toString();        // PEM
$key->getPem();          // legacy alias of toString()
(string) $key;           // PEM
```

Load failures throw `RuntimeException: Unable to load the private key [..].` ;
missing files throw `InvalidArgumentException: Private key file [..] not
found.`.

`getSelfSignedCert(Csr\Csr $request, int $days = 365)` self-signs a CSR with
this key — see the [CSR docs](csr.md).

## PublicKey — `Strukt\Ssl\PublicKey`

Mirror of `PrivateKey` for the public half.

```php
use Strukt\Ssl\PublicKey;

$key = PublicKey::read('keys/alice.pub.pem');
$key = PublicKey::make($pem);
$key = PublicKey::fromKey($resource);   // re-serialises via OpenSSL details

$key->get();            // OpenSSLAsymmetricKey
$key->getResource();    // legacy alias of get()
$key->getKey();         // openssl_pkey_get_details() array|false
$key->getPem();         // PEM
```

`fromKey()` re-parses the *public* PEM out of the key details rather than
holding the resource for both halves — the same object can then freely wrap
either side of a generated pair.

## PublicKeyList — `Strukt\Ssl\PublicKeyList`

Ordered collection of public keys used as the recipient set for sealing.

```php
use Strukt\Ssl\PublicKey;
use Strukt\Ssl\PublicKeyList;

$list = PublicKeyList::make([$pubKey, $anotherPemString]);
$list->addKey($yetAnotherKey);   // PublicKey object or PEM string
$list->getKeys();                // PublicKey[]
count($list);                    // int
```

Members may be added as `PublicKey` objects or PEM strings; `getKeys()` always
hands back fingerprint-stable `PublicKey` objects suitable for OpenSSL.

## Cipher — `Strukt\Ssl\Cipher`

Asymmetric encryption line. Encrypts with the public side only, so **any
holder of the public key can push ciphertext at the pair**; decryption uses the
private side (with a public-decrypt fallback for symmetric/legacy payloads).

```php
use Strukt\Ssl\Cipher;

$cipher = new Cipher($pair);

$boxed = $cipher->encrypt('classified');     // base64 RSA ciphertext
$cipher->decrypt($boxed);                    // 'classified'
```

```php
use Strukt\Ssl\Cipher;
use Strukt\Ssl\PublicKey;

// one-shot encryption for any public half
$boxed = Cipher::encryptWith(PublicKey::read('keys/alice.pub.pem'), 'classified');
```

`decrypt()` throws `RuntimeException` on `malformed base64` or an OpenSSL
failure. `encrypt()` throws when OpenSSL rejects the payload (input larger than
the RSA modulus, etc.).

## Signer — `Strukt\Ssl\Signer`

Asymmetric signature line: sign with the private half, verify with the public
half. Signatures are SHA-256 RSA (`OPENSSL_ALGO_SHA256`), base64-encoded.

```php
use Strukt\Ssl\Signer;

$signer = new Signer($pair);
$signature = $signer->create('the document');       // base64
$signer->check('the document', $signature);         // true
```

Using a bare public key without a full pair (the common "I only trust this
peer's cert" workflow):

```php
use Strukt\Ssl\Signer;
use Strukt\Ssl\PublicKey;

$ok = Signer::verify('the document', $signature, PublicKey::read('keys/alice.pub.pem'));
```

`create()` throws `RuntimeException: No private key available for signing.`
when the pair has no private half, and `Unable to sign the data [..].` on
OpenSSL failure. `check()`/`verify()` return a bool and never throw on a
bad signature.