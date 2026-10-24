# Facade and global helpers

Two ways to reach the toolbox: the `Strukt\Ssl\All` facade class, and the
global helper functions registered through the base helper registry.

## The facade — `Strukt\Ssl\All`

Static entry points decide where the key material comes from; methods chain
into a named `Request` or `useCipher` for the operations. The anonymous chain
classes of the legacy facade are replaced by the compact value objects in this
package.

### Getting a facade

| Entry point | Key material |
| --- | --- |
| `All::makeKeys()` | a freshly generated pair on disk (`keys/key`) |
| `All::useKeys(KeyPair $keys)` | an existing pair |
| `All::keyPath(string $path)` | a private-key file (public half derived; dir and name parsed from the path) |
| `All::makeKeysByCfg(?Config $config = null)` | a new pair honouring a custom `Config` |

```php
use Strukt\Ssl\All;

$tool = All::makeKeys();
$tool = All::useKeys($pair);
$tool = All::keyPath('keys/alice.pem');
```

The underlying carrier is reachable via `getKeys(): KeyPairInterface`.

### Operations

```php
// Encrypt a message for the pair's public half
$tool->toSend('classified');

// The asymmetric cipher on the facade's keys
$tool->useCipher()->encrypt('classified');

// Certificate flow for an on-disk certificate
$tool->withCert('keys/cert.pem', ['common' => 'strukt.example'])->verify();

// CSR pipeline from the facade's keys
$tool->useCsr(['common' => 'strukt.example'])->selfSign(365)->getCert();

// Envelope twin; picks the recipient half
\Strukt\Ssl\All::withEnvl($iv, $privKey);   // Pockets
```

| Member | Signature | Notes |
| --- | --- | --- |
| `withCert` | `withCert(string $path, array $names = ['common' => 'test'])` | adopt a cert, returns `Request` |
| `useCsr` | `useCsr(array $names = ['common' => 'test'])` | build a CSR pipeline, returns `Request` |
| `useCipher` | `useCipher(): Cipher` | cipher line on the facade's keys |
| `toSend` | `toSend(string $message): string` | base64 ciphertext via `Cipher::encryptWith($publicKey, ...)` |
| `withEnvl` | `static withEnvl(?string $iv = null, ?PrivateKey $privKey = null): Envelope\Pockets` | envelope pocket; caller picks the recipient half |
| `getKeys` | `getKeys(): KeyPairInterface` | the carrier |

`makeKeysByCfg()` stores the `Config` as a package-level default used by later
`useCsr()` calls in the same process.

## Global helpers

Registered through the Strukt base helper registry (guarded with
`function_exists` + `helper_add`, so redeclaration is impossible). Each secret
is an explicit parameter — nothing is read from a config file.

### `codec` — symmetric codec

```php
$codec = codec('a-strong-key');                 // Codec, random IV per message
$codec = codec('a-strong-key', 'AES-256-CBC', $ivHex);   // fixed vector
```

### `bcry` — bcrypt bound to one password

```php
$bcry = bcry('p@55w0rd');                        // cost defaults to 12

$bcry->encode();                                 // digest
$bcry->verify($storedHash);                      // bool
```

### `sha256` / `sha256dbl`

```php
sha256('abc');       // single SHA-256 hex
sha256dbl('abc');    // double SHA-256 hex
```

### `csrf` — maker or validator

```php
$csrf = csrf(['user' => 42], 'csrf-key', 300);

$token = $csrf->encode();        // mint a token
$csrf->decode();                 // {data, iat, eat} claims
$csrf->valid();                  // bool
```

### `jwt` — maker or validator

```php
jwt(['role' => 'admin'], 'jwt-secret');   // string token (array in → mint)

$claims = jwt($token, 'jwt-secret');      // token string in → validate
$claims->valid();                         // bool
$claims->yield();                         // \stdClass claim set
```

Signing options are passed positionally: `jwt($data, $secret, $algo =
'HS256', $expire = 3600)`.

### `ssl` — entry point into the facade

```php
ssl();                              // All::makeKeys()
ssl($pair);                         // All::useKeys($pair)
ssl($config);                       // All::makeKeysByCfg($config)
ssl('keys/alice.pem');              // All::keyPath($path) when the path is a file
ssl($keyPairInterface);             // new All($arg)
```

### `keypair` — build or adopt a pair

```php
keypair();                                    // KeyPairBuilder::make('keys/', 'key')->makeKeyPair()
keypair('keys/alice.pem', 'keys/', 'alice');  // adopt an existing private key
```

### `pubkey` — load a public key from a PEM file

```php
pubkey('keys/alice.pub.pem');       // PublicKey
```

### Signature summary

| Helper | Signature |
| --- | --- |
| `codec` | `codec(string $key, string $cipher = 'AES-128-CBC', ?string $vector = null): Codec` |
| `bcry` | `bcry(string $password, int $cost = 12): object` — `encode(): string`, `verify(string $hash): bool` |
| `sha256` | `sha256(string $input): string` |
| `sha256dbl` | `sha256dbl(string $input): string` |
| `csrf` | `csrf(array\|string $data, string $key = 'csrf', int $duration = 300): object` — `encode()`, `decode()`, `valid()` |
| `jwt` | `jwt(array\|string $data, string $secret, string $algo = 'HS256', int $expire = 3600): string\|object` |
| `ssl` | `ssl(KeyPair\|KeyPairInterface\|Config\|string\|null $arg = null): All` |
| `keypair` | `keypair(?string $privateKeyPath = null, string $dir = 'keys/', string $name = 'key'): KeyPair` |
| `pubkey` | `pubkey(string $path): PublicKey` |