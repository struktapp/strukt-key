<?php

use Strukt\Ssl\Cipher;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\Signer;

beforeEach(function () {
    $this->pair = KeyPair::make(key_temp_dir(), 'alice');
});

it('encrypts with public half and decrypts with private half', function () {
    $cipher = new Cipher($this->pair);
    $secret = 'classified';

    $cipherText = $cipher->encrypt($secret);

    expect($cipher->decrypt($cipherText))->toBe($secret);
});

it('static encryptWith produces data the pair can read', function () {
    $cipherText = Cipher::encryptWith($this->pair->publicKey(), 'broadcast');

    expect((new Cipher($this->pair))->decrypt($cipherText))->toBe('broadcast');
});

it('signs and verifies', function () {
    $signer = new Signer($this->pair);
    $signature = $signer->create('the document');

    expect($signer->check('the document', $signature))->toBeTrue()
        ->and($signer->check('tampered', $signature))->toBeFalse();
});

it('static verify checks a bare public key', function () {
    $signer = new Signer($this->pair);
    $signature = $signer->create('signed by alice');

    expect(Signer::verify('signed by alice', $signature, $this->pair->publicKey()))->toBeTrue();
});