# Symmetric encryption

`Strukt\Codec` is a symmetric AES encoder/decoder backed by the OpenSSL cipher
API. It supports every cipher in `openssl_get_cipher_methods()` (e.g.
`AES-128-CBC` default, `AES-256-CBC`, `AES-256-GCM`).

## The safe default: a random IV per message

The legacy class only worked when the caller supplied a fixed IV through a
config file. This rebuild keeps that mode for compatibility and adds the safer
default: when no vector is given, a fresh CSPRNG IV is generated for **every**
message and carried along in the result, so the same key can be reused without
IV reuse.

## Result shapes

| Mode | `encode()` returns |
| --- | --- |
| Fixed IV supplied | bare base64 ciphertext |
| No IV (default) | `<iv-hex>:<base64 ciphertext>` |

`decode()` recognises the wrapped form and splits it back apart.

## Example

```php
use Strukt\Codec;

$codec = Codec::make('a-strong-key');          // random IV per message
$wrapped = $codec->encode('classified');
// "b91f...:<base64>" — the IV rides along

$codec->decode($wrapped);                      // 'classified'
```

Fixed IV mode, for deterministic vectors or interop:

```php
use Strukt\Codec;

$iv = '00112233445566778899aabbccddeeff';       // hex, matches AES-128-CBC's 16 bytes
$codec = Codec::make('a-strong-key', 'AES-128-CBC', $iv);
$cipherText = $codec->encode('classified');     // bare base64
$codec->decode($cipherText);                    // 'classified'
```

## API

### `new Codec(string $key, string $cipher = 'AES-128-CBC', ?string $vector = null)`

Constructor. Validates in order:

1. The cipher is in `openssl_get_cipher_methods()` (case-insensitive join) —
   otherwise `InvalidArgumentException: Unsupported cipher [..].`
2. When a vector is supplied: it must be valid hex, and its byte length must
   equal `openssl_cipher_iv_length($cipher)` — otherwise
   `InvalidArgumentException` with a descriptive message.

### `static make(...)` — same parameters, returns `Codec`

Convenience factory equivalent to `new self(...)`.

### `encode(string $data): string`

Encrypts with `OPENSSL_RAW_DATA`. Result shape depends on the mode (see above).
On OpenSSL failure throws `RuntimeException: Unable to encrypt the payload.`

### `decode(string $encrypted): string`

Decrypts either form produced by `encode()`. On failure (wrong key, wrong IV,
tampered data, malformed base64/IV) throws:

```text
RuntimeException: Unable to decrypt the payload [..]
```

The message distinguishes `malformed base64`, `malformed IV`, and `missing IV`
(from trying to `decode()` a bare value against a random-IV codec).

## Errors

Rather than the legacy silent failures, every impossible operation raises a
typed exception with a bracket-dialect message (`Unable to ... [reason].`),
matching the rest of the Strukt components.

## FixVector — `Strukt\Ssl\FixVector`

Random IV generation for the symmetric ciphers. The job is small: ask OpenSSL
for the cipher's IV length and fill it with CSPRNG bytes
(`random_bytes`, not the legacy `openssl_random_pseudo_bytes`).

```php
use Strukt\Ssl\FixVector;

$iv = FixVector::make('AES-128-CBC');   // raw bytes
$iv = FixVector::hex('AES-128-CBC');    // hex, convenient for config files
```

It backs the random-IV mode of `Codec` and `Envelope`.