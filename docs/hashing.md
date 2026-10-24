# Hashing

The hashing surface lives in `Strukt\Hash` and covers password hashing with
bcrypt and message digests with the SHA family.

## Bcrypt — `Strukt\Hash\Bcrypt`

Password hashing that delegates to PHP's native `password_hash()` /
`password_verify()`. The rebuild drops the legacy `crypt()` salt built with
`mt_rand()`; the native calls generate the salt from the CSPRNG and embed the
cost in the digest so verification always reuses the original work factor.

```php
use Strukt\Hash\Bcrypt;

$hash = (new Bcrypt())->makeHash('p@55w0rd');

(new Bcrypt())->verify('p@55w0rd', $hash);   // true
(new Bcrypt())->verify('wrong', $hash);      // false
```

### Constructor

`new Bcrypt(int $cost = 12)` — the work factor, a power of two between `4` and
`31`. Out of range throws `InvalidArgumentException`. The default `12` closely
matches the native PHP default.

### Methods

| Method | Signature | Returns |
| --- | --- | --- |
| `makeHash` | `makeHash(string $password): string` | A `$2y$` bcrypt digest with the cost embedded. |
| `verify` | `verify(string $password, string $hash): bool` | Constant-time match check. |
| `needsRehash` | `static needsRehash(string $hash, int $cost = 12): bool` | True when the digest uses an older algorithm or cost. |

### Rehash guidance

`needsRehash()` powers the common "hash at login time if stale" pattern — call
it after a successful `verify()` and re-store the upgraded digest when it
reports `true`:

```php
if ((new Bcrypt())->verify($password, $stored) && Bcrypt::needsRehash($stored, 14)) {
    $stored = (new Bcrypt(14))->makeHash($password);   // persist this
}
```

## Sha — `Strukt\Hash\Sha`

Message digests and keyed HMAC lines over the native `hash()` primitives. The
one- and double-SHA256 forms match the legacy helper surface; the generic
methods reach the rest of the `hash_algos()` family.

```php
use Strukt\Hash\Sha;

Sha::once256('abc');     // ba7816bf... (SHA-256 hex)
Sha::dbl256('abc');      // hash(hash('abc'))
Sha::once('abc', 'sha512');
Sha::dbl('abc', 'sha256');
Sha::hmac('key', 'data', 'sha256');   // raw binary HMAC
```

### Methods

| Method | Signature | Returns |
| --- | --- | --- |
| `once` | `static once(string $text, string $algo = 'sha256'): string` | Hex digest of one round. |
| `dbl` | `static dbl(string $text, string $algo = 'sha256'): string` | Hex digest of `hash(hash($text))`. |
| `hmac` | `static hmac(string $key, string $data, string $algo = 'sha256'): string` | **Raw binary** HMAC (binary output for composition, e.g. the JWT signer). |
| `once256` | `static once256(string $text): string` | Single SHA-256 hex digest. |
| `dbl256` | `static dbl256(string $text): string` | Double SHA-256, used by block-chain address derivation. |

### Usage notes

- `once`/`dbl`/`hmac` accept any algorithm from `hash_algos()`; passing an
  unknown name raises the native `ValueError` (PHP 8+).
- `dbl()` and `dbl256()` operate on the **hex** output of the first round
  (byte-level `hash(hash(x))`), matching the legacy double-hash semantics.
- `hmac()` returns raw bytes rather than hex — wrap it in `bin2hex()` when a
  printable token is wanted.