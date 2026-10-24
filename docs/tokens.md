# Tokens

Two token types live at the top namespace: `Strukt\Jwt` (JSON Web Tokens) and
`Strukt\Csrf` (cross-site request forgery tokens). Both are self-contained —
no external packages, no network calls, no config file.

## JWT — `Strukt\Jwt`

A self-contained HS256/384/512 signer. The legacy package wrapped
`firebase/php-jwt`; this rebuild drops the dependency and implements the line
directly over the Strukt SHA/HMAC primitives.

Token format:

```
base64url(header) . base64url(payload) . base64url(signature)
```

where the signature is `hash_hmac(secret, "header.payload", digest)` compared
in constant time with `hash_equals()`.

Claims carried by every token: `iss`, `aud` (mirrors the issuer), `iat`, `exp`,
and `data` (the caller's payload). `nbf` is honoured when present.

### Mint a token

```php
use Strukt\Jwt;

$signer = Jwt::make([
    'secret' => 'jwt-secret',
    'algo' => 'HS256',
    'expire' => 3600,
]);

$token = $signer->encode(['role' => 'admin', 'uid' => 42]);
```

### Validate

```php
$claims = $signer->decode($token);           // \stdClass, or null when invalid
$signer->valid($token);                      // bool

$claims->data->role;                         // 'admin'
```

### Constructor

`new Jwt(string $secret, string $algo = 'HS256', int $expire = 3600,
string $issuer = 'strukt/key', string $timezone = 'UTC')`

Throws `InvalidArgumentException` when `$algo` is not `HS256`/`HS384`/`HS512`,
or when `$expire < 1`. A non-UTC `$timezone` calls `date_default_timezone_set()`
so timestamps match the intended clock.

### `static make(array $options)`

`$options` keys: `secret` (**required**), `algo` (default `HS256`), `expire`
(default `3600`), `issuer` (default `strukt/key`), `timezone` (default `UTC`).

### `encode(array|string $data, ?int $issuedAt = null, ?int $expiresAt = null): string`

Issues a token. `$issuedAt` defaults to now; `$expiresAt` defaults to
`$issuedAt + expire`.

### `decode(string $token, ?int $now = null): ?\stdClass`

Returns the full claim set (`iss`, `aud`, `iat`, `exp`, `data`, plus any
`nbf`) or `null`. Decode fails — returning `null`, never throwing — when the
token:

- does not split into exactly three segments,
- has a malformed header or payload,
- was signed under a different `algo` than this signer,
- fails the constant-time signature check,
- is past `exp`, or
- is before `nbf` when present.

### `valid(string $token, ?int $now = null): bool`

`decode() !== null`.

### `static validClaims(\stdClass $claims): bool`

Legacy check on an already-decoded claim set: `time() > exp` → false (an
`exp` of 0 is treated as "no expiry").

## CSRF — `Strukt\Csrf`

A token wraps the submitted payload with issued-at (`iat`) and expires-at
(`eat`) timestamps, JSON-encodes them, and seals them with an AES codec under a
caller-provided key. Validity is decided by the window `iat <= now <= eat`, so
a token cannot outlive its slot even though the ciphertext is unreadable
without the key.

### Mint a token

```php
use Strukt\Csrf;

$token = Csrf::make(['user_id' => 42], 'csrf-key', 300)->encode();
```

`make(array|string $data, string $key, int $duration = 300)`. `$data` may be a
scalar string or an array. `$duration` must be at least `1` second
(`InvalidArgumentException` otherwise).

### Validate

```php
$claims = Csrf::decode($token, 'csrf-key');
// ['data' => ['user_id' => 42], 'iat' => ..., 'eat' => ...]

$valid = Csrf::valid($token, 'csrf-key');        // bool
```

### API

| Method | Signature | Returns |
| --- | --- | --- |
| `make` | `static make(array\|string $data, string $key, int $duration = 300)` | `static` token |
| `encode` | `encode(): string` | signed token string |
| `decode` | `static decode(string $token, string $key): array` | `{data, iat, eat}` claim set; throws `RuntimeException` on missing claims or unwrap failure |
| `valid` | `static valid(string $token, string $key, ?int $now = null): bool` | window check; `false` on any decode error, never throws |
| `__toString` | `__toString(): string` | `encode()` |

`valid()` optionally accepts a custom clock (`$now`) for tests.

## Notes

Both signers keep the secret as an explicit constructor/argument — nothing is
read from a config file, unlike the legacy package. JWTs should use a
high-entropy secret at least as long as the hash output for the chosen `algo`
(32+ bytes for HS256).