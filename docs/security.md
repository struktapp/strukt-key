# Security notes

`strukt4/key` is the hardened rewrite of `strukt1/strukt-key`. This page
collects the design decisions that changed behaviour, the threat model each
piece of the toolbox assumes, and the practical guidance that follows.

## What changed versus the legacy package

### Random IV per message

The legacy `Codec` needed a fixed IV from a config file, which invited IV reuse
(and therefore AES-CBC keystream reuse) whenever the same config was reused. In
the rebuild, omitting the vector generates a fresh CSPRNG IV per `encode()`
and carries it in the output (`<iv-hex>:<base64>`). IV reuse now has to be
someone *choosing* it, not a default. Fixed-vector mode still exists for
interop, but it is opt-in and documented as such.

### CSPRNG everywhere

- Bcrypt salts come from `password_hash()`, which draws from the OS CSPRNG —
  not the legacy `mt_rand()`-seeded `crypt()` salt.
- IV generation uses `random_bytes()` (`FixVector`, `Codec`) — not
  `openssl_random_pseudo_bytes`.
- JWT signatures are compared with `hash_equals()`, constant time.

### No cryptographic randomness from weak sources

All key material and IVs are produced by `random_bytes()` / OpenSSL / the PHP
password API. If you need deterministic behaviour (tests, golden vectors),
*that* is the only legitimate reason to pass a fixed IV or fixed seed.

### Typed errors over silent `false`

The legacy code returned booleans and writes `false` could be mistaken for
success. Every failure here surfaces as an exception with a bracket-dialect
message: `Unable to decrypt the payload [invalid key, IV, or tampered data].`,
`Unable to sign the data [...].`, and so on. Catching and re-raising is never
required to learn the failure has happened.

### Explicit secrets

Secrets are constructor/argument values, never read from a global config file.
`ssl()`, `codec()`, `csrf()`, `jwt()` all take the key explicitly. This removes
the class of bugs where a shared config silently applied the wrong secret.

## Per-primitive guidance

### Bcrypt

- Default cost `12`; the cost is embedded in the digest so verification is
  stable across upgrades.
- On successful login, call `Bcrypt::needsRehash($hash, $targetCost)` and
  transparently upgrade the stored digest when it reports `true`.
- bcrypt handles passwords up to 72 bytes by design; longer inputs are
  truncated by PHP's implementation.

### Symmetric codec

- Use the random-IV mode (the default) unless you have an interop constraint.
- The key must be high entropy (for AES-256, 32 bytes). Deriving from a
  passphrase is not done here; use a KDF such as `password_hash`/bcrypt or a
  proper PBKDF outside this package.
- The default cipher is `AES-128-CBC`. CBC requires distinct random IVs; the
  random-IV mode guarantees that. `AES-256-GCM`/`AES-256-CBC` are available via
  the `cipher` argument when the key length matches.

### RSA

- Default modulus is 2048-bit (`private_key_bits`). 3072/4096 are supported by
  the `keys:new --bits` option and `Config::with('private_key_bits', ...)`.
- `Cipher` is RSA-padding encryption — it can only encrypt payloads up to the
  modulus size minus padding. For arbitrary-length messages use `Envelope`
  (hybrid scheme) instead.
- Private keys on disk are written unwrapped (`encrypt_key` is `false` by
  default) with the directory created at mode `0775`. Guard file permissions and
  repo hygiene yourself: never commit `*.pem` or `cert.pem` files.

### Envelope (hybrid encryption)

- `openssl_seal` generates a fresh symmetric session key per close operation.
- **The IV is generated once per close and shared across all recipients.** This
  is safe because the session key is fresh per message; it is *not* safe to
  reuse an `Envelope` instance's IV across messages. Use `closeWithIv()` and
  pass the returned IV to the opener, exactly as `envelope:close` /
  `envelope:open` do.
- Each recipient's envelope key is for them only — the envelope keys list is
  positionally aligned to the recipient list, so a holder must be given *their*
  slot.

### JWT

- Self-contained HS256/384/512. No asymmetric algorithms are implemented and
  none are planned — keep the signing secret out of any client.
- The secret should be at least 32 bytes of entropy for HS256 (and longer for
  HS384/HS512); the package does not enforce a minimum.
- `decode()` returns `null` on any failure (tampering, wrong key, expiry) and
  bears no side channels: signatures use `hash_equals`, timestamps use
  server time unless `$now` is injected.

### CSRF

- The token is AES-sealed with your key and carries `iat`/`eat`. Validity is
  cryptographic (the window is inside the ciphertext), so expiry cannot be
  edited by a client.
- Bind the token to the user via the `data` payload and compare it to the
  session before acting.

### Certificate downloader

`Downloader::single()` deliberately disables peer verification — it fetches the
*certificate profile* for inspection (issuer, expiry, fingerprint), it does not
establish trust. Do not use it as the trust anchor of a TLS connection without
your own verification of the result.

## Threat model summary

- **Secrets in code**: all secrets are explicit call parameters; keep them out
  of source control and out of plain logs.
- **Key files**: generated in memory, written only on explicit `make*File()`
  calls or CLI `keys:new` / `cert:selfsign`. The CLI commands write into the
  directory you pass with `--dir` — point it outside the repo in production.
- **Nonce/IV reuse**: actively prevented by default (random IV per message,
  per-seal IV), which is the main historical weakness of the legacy package.
- **Error decoration**: failures are exceptions, so "did this encrypt?" can
  never accidentally be answered `true`.

For the equations and formats behind the token lines, see the sibling docs —
[tokens.md](tokens.md) for JWT/CSRF, [symmetric.md](symmetric.md) for the codec
shapes, [envelope.md](envelope.md) for the seal format.