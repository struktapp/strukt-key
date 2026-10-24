# Installation

`strukt/key` requires PHP 8.2+ with the OpenSSL extension (`ext-openssl`) and
the `hash` extension. No other runtime services are involved.

## Composer

From your project root:

```bash
composer require strukt/key
```

This sets the `Strukt\` autoload namespace, merges the package helpers into
the Strukt helper registry, and registers the `kcli` executable under
`vendor/bin`.

In the repository itself, `strukt/key` is wired to its sibling components with
path repositories (`strukt4/base`, `strukt4/commons`, `strukt4/console`,
`strukt4/fs`, `strukt4/math`), so a plain `composer install` inside the package
is enough to develop and test it:

```bash
cd strukt4/key
composer install
```

## The binary

The package ships a CLI executable registered in `composer.json`'s `bin`:

```bash
vendor/bin/kcli <command> [arguments] [options]
```

With no arguments (or `--help` / `-h`), `kcli` lists every command and its
description.

For development inside the package the same binary is at `bin/kcli` and can be
run directly (`./bin/kcli ...`) or through `php bin/kcli ...`.

## Version

`kcli version` reports the package release (`0.1.0` at the time of writing).

## Test and lint scripts

```bash
composer test
composer lint
```

`composer test` runs the Pest suite (`phpunit.xml` is bundled); `composer lint`
runs `php -l` over every PHP file under `src`.