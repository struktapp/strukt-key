<?php

use Strukt\Csrf;

it('mints and validates a token in its window', function () {
    $token = Csrf::make(['user' => 42], 'csrf-key', 300)->encode();

    expect(Csrf::valid($token, 'csrf-key'))->toBeTrue()
        ->and(Csrf::decode($token, 'csrf-key')['data'])->toBe(['user' => 42]);
});

it('handles string payloads', function () {
    $token = Csrf::make('a-slot', 'csrf-key', 300)->encode();

    expect(Csrf::decode($token, 'csrf-key')['data'])->toBe('a-slot');
});

it('rejects a token past its window', function () {
    $now = time();
    $token = Csrf::make('slug', 'csrf-key', 5)->encode();

    expect(Csrf::valid($token, 'csrf-key', $now + 20))->toBeFalse();
});

it('rejects a token sealed under a different key', function () {
    $token = Csrf::make('slug', 'key-a', 300)->encode();

    expect(Csrf::valid($token, 'key-b'))->toBeFalse();
});

it('rejects garbage', function () {
    expect(Csrf::valid('not-a-token', 'csrf-key'))->toBeFalse();
});

it('encodes to a string', function () {
    expect((string) Csrf::make('slug', 'csrf-key', 300))->toBeString();
});