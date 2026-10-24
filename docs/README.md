# Strukt Key documentation

Cryptography, signing, and SSL utilities for PHP 8.2+, rebuilt on the
`Strukt\Math`, `Strukt\Console`, and `Strukt\Fs` components. Keys are generated
in memory and written only where you ask; nothing depends on external services,
HTTP calls, or committed key material.

Topics:

- [Installation](installation.md) — requirements, composer, the `kcli` binary.
- [Hashing](hashing.md) — `Bcrypt` and `Sha` (digests, double hashing, HMAC).
- [Symmetric encryption](symmetric.md) — `Codec` AES with random or fixed IVs.
- [Tokens](tokens.md) — self-contained `Jwt` and `Csrf`.
- [Asymmetric encryption](asymmetric.md) — `KeyPair`, `PrivateKey`, `PublicKey`,
  `Cipher`, `Signer`, `PublicKeyList`, `Config`, `FixVector`.
- [Digital envelopes](envelope.md) — `Envelope` multi-recipient sealing.
- [Certificates](certificates.md) — `Cert`, `Certificate\Parser`, `Downloader`.
- [Certificate signing requests](csr.md) — `Request`, `Csr`, `CsrBuilder`,
  `UniqueName`, self-signed and CA certificates.
- [Facade and helpers](facade.md) — `Strukt\Ssl\All` and the global helpers.
- [Command line](cli.md) — every `kcli` command.
- [Security notes](security.md) — design decisions, hashing guidance, and the
  migration away from `strukt1/strukt-key`.