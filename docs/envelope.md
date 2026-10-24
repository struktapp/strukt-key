# Digital envelopes

`Strukt\Ssl\Envelope` seals a message so that a **set** of recipients can each
open it with their own private key — the classic "many recipients, one
ciphertext" pattern.

## How it works

`openssl_seal` picks a fresh symmetric session key, encrypts the message with
it, and encrypts that session key once per recipient. The result is:

- `envelope_keys` — one base64 session key per recipient, ordered exactly as
  the recipients were given;
- `sealed` — the base64 encrypted payload;
- `iv` — the initialization vector used (raw bytes; a fresh random IV is
  generated per close operation and always returned).

Each holder recovers the message with their own envelope key (their slot in
`envelope_keys`) and the matching private key. The random-IV-per-op contract
means the same envelope can be reused for many messages without IV reuse.

## Sealing

Target recipients by certificate path or by public-key list.

```php
use Strukt\Ssl\Envelope;

[$envKeys, $sealed, $iv] = Envelope::withAlgo()
    ->useCerts(['recipients/alice.pem', 'recipients/bob.pem'])
    ->closeWithIv('the message');
// $envKeys: [base64, base64]  — one per recipient
// $sealed : base64 payload
// $iv     : raw bytes
```

```php
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PublicKey;
use Strukt\Ssl\PublicKeyList;

$list = PublicKeyList::make([PublicKey::read('alice.pub.pem'), PublicKey::read('bob.pub.pem')]);

[$envKeys, $sealed, $iv] = Envelope::withAlgo()->useKeys($list)->closeWithIv('the message');
```

A fixed IV may be forced (discouraged — use the random IV for normal use):

```php
$envelope = Envelope::withAlgo($iv, 'AES-128-CBC');
$envelope->useCerts($paths)->close($data);   // returns [envKeys, sealed] only
```

## Opening

Each recipient opens with their own slot in `envelope_keys`, the sealed
payload, the IV, and their private key:

```php
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PrivateKey;

$pockets = Envelope::withAlgo($iv)->usePrivKey(PrivateKey::read('keys/bob.pem'));

$message = $pockets->open($envKeys[0], $sealed);   // 'the message'
```

A wrong envelope key or private key throws:

```text
RuntimeException: Unable to open the message [..]
```

## API summary

### Envelope

| Member | Purpose |
| --- | --- |
| `__construct(string $cipher = 'AES-128-CBC', ?string $iv = null)` | Cipher from `openssl_get_cipher_methods()`; `null` IV = random per operation. |
| `static withAlgo(?string $iv = null, string $cipher = 'AES-128-CBC')` | Factory. |
| `useCerts(array $paths): Pockets` | Recipients by certificate PEM path; extracts each cert's public key. |
| `useKeys(PublicKeyList\|array $keys): Pockets` | Recipients from a `PublicKeyList` or a raw array. |
| `usePrivKey(PrivateKey $privKey): Pockets` | The recipient's private key for opening. |
| `static closeAllWith(PublicKeyList $list, string $data, string $cipher = 'AES-128-CBC'): array` | One-shot: returns `[envKeys, sealed, iv]`. |

### Envelope\Pockets

The pocket returned by the targeting methods — one half of an envelope
operation.

| Member | Purpose |
| --- | --- |
| `close(string $data): array{0: string[], 1: string}` | `[envKeys, sealed]`. |
| `closeWithIv(string $data): array{0: string[], 1: string, 2: string}` | `[envKeys, sealed, iv]` — reports the IV used. |
| `open(string $envKey, string $sealed): string` | The original message, or throws. |

`Pockets` is constructed with either the recipient public-key set (to `close`)
or a private key (to `open`); calling the wrong operation throws
`RuntimeException: No recipients loaded for sealing.` /
`No private key loaded for opening.`.

## Notes

- Envelope keys are **reported base64** and the IV is **raw bytes**; the CLI
  layer hex-encodes the IV to keep it printable, and the [CLI docs](cli.md#envelope-close)
  show the string that must round-trip.
- The cipher is validated against `openssl_get_cipher_methods()` at `Envelope`
  construction (case-insensitive), mirroring `Codec`.