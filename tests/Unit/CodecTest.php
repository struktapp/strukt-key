<?php

use Strukt\Codec;

it('encrypts and decrypts a round trip', function () {
    $codec = Codec::make('a-key-for-testing');
    $secret = 'attack at dawn';

    expect($codec->decode($codec->encode($secret)))->toBe($secret);
});

it('generates a fresh iv per message when none is given', function () {
    $codec = Codec::make('a-key-for-testing');

    $first = $codec->encode('same input');
    $second = $codec->encode('same input');

    expect(explode(':', $first, 2)[0])->not->toBe(explode(':', $second, 2)[0]);
});

it('wrapper carries the iv and decodes without it being shared', function () {
    $codec = Codec::make('a-key-for-testing');
    $wrapped = $codec->encode('hello');

    expect($codec->decode($wrapped))->toBe('hello');
});

it('supports a fixed hex vector for interop', function () {
    $vector = bin2hex(random_bytes(openssl_cipher_iv_length('AES-128-CBC')));
    $codec = Codec::make('a-key-for-testing', 'AES-128-CBC', $vector);

    $cipherText = $codec->encode('pinned');

    expect($codec->decode($cipherText))->toBe('pinned')
        ->and(str_contains($cipherText, ':'))->toBeFalse();
});

it('fails loudly on a wrong key', function () {
    (Codec::make('a-key-for-testing'))->decode((Codec::make('other-key'))->encode('boom'));
})->throws(RuntimeException::class, 'Unable to decrypt');

it('rejects an unbalanced vector', function () {
    Codec::make('key', 'AES-128-CBC', '00');
})->throws(InvalidArgumentException::class, 'does not match cipher');

it('wraps with the requested cipher name', function () {
    $codec = Codec::make('a-key-for-testing', 'AES-256-CBC');

    expect($codec->encode('x'))->toContain(':');
});