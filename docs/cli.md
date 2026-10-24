# Command line

`strukt/key` ships the `kcli` executable registered in `composer.json`'s `bin`.
Run it from a console:

```
./vendor/bin/kcli <command> [arguments] [options]
```

With no arguments (or `--help` / `-h`), `kcli` lists every command and its
description. Inside the package the same binary is `./bin/kcli`.

## Conventions

### Input resolution

Commands that consume a message (`hash`, `enc`, `dec`, `sign`, `verify`,
`envelope:close`) accept the payload any of three ways:

- a positional `data` argument (quote it), and/or
- `--file=<path>` to read it from a file, and/or
- piped standard input.

Resolution order is the same everywhere: `--file` first, then the `data`
argument, then stdin.

### Secrets

Symmetric-secret commands (`enc`/`dec`, `csrf`, `csrf:check`, `jwt:encode`,
`jwt:decode`) take the secret either as the positional `secret` argument or as
`--secret=<value>`; `--secret` wins when both are given. Missing secrets throw:
`A secret is required, pass --secret=<value>.`

### Output

Every command accepts `--json` as a flag. Without it a plain-text report is
printed (banner `Strukt Key — <command>` then `key: value` pairs, nested maps
indented); with it the result is pretty-printed JSON (`JSON_PRETTY_PRINT` +
`JSON_UNESCAPED_UNICODE`). A few commands (`cert:xpub`, `envelope:open`) print
the raw payload instead of a report, with `--json` wrapping it in an object.

### Exit codes

Success exits `0`. Commands that validate something return `0` when valid and
`1` when invalid (`bcrypt:check`, `verify`, `cert:verify`, `jwt:decode`,
`csrf:check`). Missing required arguments/options raise an error (non-zero).
Errors carry bracket-dialect messages (`Unable to read file [x].`).

## Commands

### version

```
./vendor/bin/kcli version --json
```

Reports the package release. JSON: `version` (`0.1.0`).

### hash

```
./vendor/bin/kcli hash "hello world" --json
cat file.txt | ./vendor/bin/kcli hash --type=sha512
```

Computes a message digest. `--type` (`sha256` default; `sha256,sha512,sha1,
md5,sha256dbl`), `--file`. `sha256dbl` applies the digest twice (double SHA-256).
JSON: `type`, `hash`.

### bcrypt

```
./vendor/bin/kcli bcrypt "p@ssw0rd" --cost=12 --json
```

Hashes a password with bcrypt. `--cost` (int, default `12`). JSON: `cost`,
`hash`.

### bcrypt:check

```
./vendor/bin/kcli bcrypt:check "p@ssw0rd" '$2y$12$...' --json
```

Checks a password against a stored bcrypt digest. JSON: `valid`. Exit `0`
when valid, `1` when not.

### keys:new

```
./vendor/bin/kcli keys:new --dir=keys/ --name=alice --bits=2048 --json
```

Generates an RSA key pair on disk. Options: `--dir` (`keys/` default),
`--name` (`key` default, base file name without extension), `--bits` (int,
`2048` default). Writes `<dir>/<name>.pem` and `<dir>/<name>.pub.pem`, creating
the directory (mode `0775`) when needed. JSON: `private`, `public`, `bits`.

### enc

```
./vendor/bin/kcli enc "top secret" "a-strong-key" --json
./vendor/bin/kcli enc --file=document.txt "a-strong-key"
```

Encrypts data with AES. `--cipher` (`AES-128-CBC` default), `--vector` (fixed
hex IV; when absent a random IV is generated and reported), `--file`, `--json`.
JSON: `cipher`, `ciphertext`, and `iv` (hex) when the IV was random.

### dec

```
./vendor/bin/kcli dec "$CIPHERTEXT" "a-strong-key" --json
```

Decrypts data produced by `enc`. `--cipher`, `--vector` (for ciphertext that
carries no IV), `--file`, `--json`. JSON: `plain`. Wrong key/IV/tampered data
raise a decryption error.

### sign

```
./vendor/bin/kcli sign "the document" --key=keys/alice.pem --json
```

Signs data with a private key. `--key` (**required**, PEM path). JSON:
`signature`.

### verify

```
./vendor/bin/kcli verify "the document" "$SIG" --key=keys/alice.pub.pem --json
```

Verifies a signature against data and a public key. `--key` (**required**, PEM
path to the public key). JSON: `valid`. Exit `0` valid, `1` invalid.

### cert:selfsign

```
./vendor/bin/kcli cert:selfsign --dir=keys/ --name=web --days=365 --cert=cert.pem --common=strukt.example --org=Strukt --json
```

Generates a key pair and a self-signed certificate. Options: `--dir` (`keys/`),
`--name` (`key`), `--days` (int, `365`), `--cert` (`cert.pem`, written into the
directory), `--common` (`localhost`), `--org`, `--orgUnit`, `--email`. Writes
`<dir>/<name>.pem`, `<dir>/<name>.pub.pem`, and `<dir>/<cert>`. JSON:
`private`, `public`, `cert`, `subject`.

### cert:verify

```
./vendor/bin/kcli cert:verify keys/cert.pem --key=keys/web.pem --json
```

Verifies a certificate, optionally against a private key. Positional `cert`
(path to the PEM, **required**); `--key` (private key to match against the
certificate). JSON: `valid`, `expired`, `subject`, `issuer`. When `--key` is
given, `valid` reflects whether the certificate matches the private key. Exit
`0` when `valid && !expired`, else `1`.

### cert:xpub

```
./vendor/bin/kcli cert:xpub keys/cert.pem --json
```

Extracts the public key embedded in a certificate. Prints the PEM directly;
`--json` wraps it as `public_key`.

### cert:info

```
./vendor/bin/kcli cert:info keys/cert.pem --json
```

Reads the interesting fields of a certificate. JSON: `subject` (domain),
`issuer`, `signature_algo`, `valid_from`, `valid_to` (Y-m-d H:i:s), `expired`,
`self_signed`, `fingerprint`.

### jwt:encode

```
./vendor/bin/kcli jwt:encode '{"role":"admin","uid":42}' "jwt-secret" --json
```

Mints a JSON web token. Payload and secret are positional; `--algo` (`HS256`
default; `HS256,HS384,HS512`), `--ttl` (int, `3600`). JSON: `token`. The
payload must be valid JSON (throws otherwise).

### jwt:decode

```
./vendor/bin/kcli jwt:decode "$TOKEN" "jwt-secret" --json
```

Decodes and validates a JSON web token. `--algo` (`HS256` default) must match
the algorithm the token was minted with. JSON: `valid`, and `claims` when
valid (iss/aud/iat/exp/data). Exit `0` valid, `1` invalid.

### envelope:close

```
./vendor/bin/kcli envelope:close "letter" "ca.pem,another.pem" --json
```

Seals a message for a set of recipients. Positionals: `data` (or `--file`) and
`recipients` (comma-separated paths to recipient certificate PEMs — each gets
its own envelope key). Options: `--cipher` (`AES-128-CBC`), `--iv` (fixed hex
IV; a random one is generated and reported when empty). JSON:
`envelope_keys` (list, one per recipient), `sealed`, `iv` (hex). At least one
recipient is required (`At least one recipient certificate is required.`).

### envelope:open

```
./vendor/bin/kcli envelope:open "$ENV_KEY" "$SEALED" "$IV_HEX" --key=keys/bob.pem --json
```

Opens a sealed message with the recipient's private key. Positionals:
`env-key` (base64), `sealed` (base64), `iv` (hex). `--key` (**required**),
`--cipher` (`AES-128-CBC`). Prints the original message directly; `--json`
wraps it as `data`. The IV must be valid hex.

### csrf

```
./vendor/bin/kcli csrf '{"user":42}' "csrf-key" --ttl=300 --json
```

Mints a cross-site request forgery token. Payload parses as JSON when possible,
otherwise stays a string. `--ttl` (int, `300`). JSON: `token`.

### csrf:check

```
./vendor/bin/kcli csrf:check "$TOKEN" "csrf-key" --json
```

Checks a CSRF token against a key. JSON: `valid`. Exit `0` valid, `1` invalid.

## Pipeline example

```bash
kcli_dir=keys
./bin/kcli keys:new --dir=$kcli_dir --name=alice --bits=2048

message="the document"
sig=$(./bin/kcli sign "$message" --key=$kcli_dir/alice.pem)
./bin/kcli verify "$message" "$sig" --key=$kcli_dir/alice.pub.pem && echo "signature OK"

# seal a letter for alice's certificate
./bin/kcli cert:selfsign --dir=$kcli_dir --name=alice --common=alice.example
closed=$(./bin/kcli envelope:close "letter" "$kcli_dir/cert.pem")
# -- then a holder picks envelope_keys[0] and runs envelope:open with alice.pem
```

Every command is also usable as a library — the CLI classes are thin wrappers
around the toolbox classes documented in the other topics.