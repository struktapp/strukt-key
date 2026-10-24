<?php

use Strukt\Hash\Bcrypt;

it('hashes and verifies a password', function () {
    $hash = (new Bcrypt())->makeHash('p@55w0rd');

    expect($hash)->toMatch('#^\$2[ayb]\$12\$#')
        ->and((new Bcrypt())->verify('p@55w0rd', $hash))->toBeTrue()
        ->and((new Bcrypt())->verify('wrong', $hash))->toBeFalse();
});

it('honors the requested cost', function () {
    $hash = (new Bcrypt(10))->makeHash('secret');

    expect($hash)->toMatch('#^\$2[ayb]\$10\$#');
});

it('rejects an out-of-range cost', function () {
    (new Bcrypt(3))->makeHash('secret');
})->throws(InvalidArgumentException::class, 'outside 4..31');

it('detects digests that need rehashing', function () {
    $hash = (new Bcrypt(10))->makeHash('secret');

    expect(Bcrypt::needsRehash($hash, 12))->toBeTrue()
        ->and(Bcrypt::needsRehash($hash, 10))->toBeFalse();
});