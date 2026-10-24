<?php

use Strukt\Jwt;

it('mints and validates a token', function () {
    $signer = Jwt::make(['secret' => 'jwt-secret']);
    $token = $signer->encode(['role' => 'admin']);

    $claims = $signer->decode($token);

    expect($signer->valid($token))->toBeTrue()
        ->and($claims->data)->toBe(['role' => 'admin'])
        ->and($claims->iss)->toBe('strukt/key');
});

it('rejects an expiry in the past at the given clock', function () {
    $now = time();
    $signer = Jwt::make(['secret' => 'jwt-secret', 'expire' => 60]);
    $token = $signer->encode(['x' => 1], issuedAt: $now);

    expect($signer->decode($token, $now + 61))->toBeNull();
});

it('rejects a token signed under another secret', function () {
    $token = Jwt::make(['secret' => 'secret-a'])->encode(['x' => 1]);
    $other = Jwt::make(['secret' => 'secret-b']);

    expect($other->valid($token))->toBeFalse();
});

it('rejects a tampered body', function () {
    $signer = Jwt::make(['secret' => 'jwt-secret']);
    $token = $signer->encode(['x' => 1]);

    $segments = explode('.', $token);
    $segments[1] = 'A' . substr($segments[1], 1);

    expect($signer->valid(implode('.', $segments)))->toBeFalse();
});

it('supports the hs384 and hs512 lines', function (string $algo) {
    $signer = Jwt::make(['secret' => 'jwt-secret', 'algo' => $algo]);
    $token = $signer->encode(['x' => 1]);

    expect($signer->valid($token))->toBeTrue();
})->with(['HS384', 'HS512']);

it('rejects an unsupported algorithm', function () {
    Jwt::make(['secret' => 'x', 'algo' => 'RS256']);
})->throws(InvalidArgumentException::class, 'Unsupported jwt algorithm');

it('rejects malformed tokens', function () {
    $signer = Jwt::make(['secret' => 'jwt-secret']);

    expect($signer->decode('not-a-jwt'))->toBeNull()
        ->and($signer->decode('a.b'))->toBeNull();
});