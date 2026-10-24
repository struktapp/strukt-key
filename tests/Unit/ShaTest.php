<?php

use Strukt\Hash\Sha;

it('computes known sha256 digests', function () {
    expect(Sha::once256('abc'))->toBe(hash('sha256', 'abc'));
});

it('computes double sha256', function () {
    expect(Sha::dbl256('abc'))->toBe(hash('sha256', hash('sha256', 'abc')));
});

it('computes hmac over the given algorithm', function () {
    $hmac = Sha::hmac('key', 'message', 'sha512');

    expect(bin2hex($hmac))->toBe(hash_hmac('sha512', 'message', 'key'));
});

it('supports the generic algorithm surface', function () {
    expect(Sha::once('abc', 'sha1'))->toBe(hash('sha1', 'abc'));
});