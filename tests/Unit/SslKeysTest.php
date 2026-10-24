<?php

use Strukt\Ssl\Config;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\PrivateKey;
use Strukt\Ssl\PublicKey;

beforeEach(function () {
    $this->dir = key_temp_dir();
});

it('generates a pair and writes both key files', function () {
    $pair = KeyPairBuilder::make($this->dir, 'alice')->makeKeyPair();

    expect($pair->privateKeyFile())->toContain('alice.pem')
        ->and($pair->makePrivateKeyFile())->toBeFile()
        ->and($pair->makePublicKeyFile())->toBeFile()
        ->and(file_get_contents($pair->publicKeyFile()))->toContain('BEGIN PUBLIC KEY');
});

it('derives a matching public key from the private half', function () {
    $private = KeyPair::make($this->dir, 'alice')->privateKey();
    $public = $private->getPublicKey();

    expect($public->toString())->toContain('BEGIN PUBLIC KEY');
});

it('round-trips private keys through pem', function () {
    $pair = KeyPair::make($this->dir, 'alice');

    $loaded = PrivateKey::read($pair->makePrivateKeyFile());

    expect($loaded->toString())->toBe($pair->privateKey()->toString());
});

it('round-trips public keys through pem', function () {
    $pair = KeyPair::make($this->dir, 'alice');

    $loaded = PublicKey::read($pair->makePublicKeyFile());

    expect($loaded->toString())->toBe($pair->publicKey()->toString());
});

it('honors the config bits override', function () {
    $pair = KeyPair::make($this->dir, 'tiny', ['private_key_bits' => 1024]);

    expect($pair->publicKey()->getKey()['bits'])->toBe(1024);
});

it('exposes default generation options', function () {
    $config = Config::dump();

    expect($config['private_key_bits'])->toBe(2048)
        ->and($config['private_key_type'])->toBe(OPENSSL_KEYTYPE_RSA)
        ->and($config['config'])->toBe(realpath(__DIR__ . '/../../asset/openssl.cnf'));
});

it('fails when loading a missing private key', function () {
    PrivateKey::read($this->dir . 'nope.pem');
})->throws(InvalidArgumentException::class, 'not found');