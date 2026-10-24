<?php

use Strukt\Ssl\Envelope;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\PrivateKey;
use Strukt\Ssl\PublicKeyList;

beforeEach(function () {
    $this->alice = KeyPair::make(key_temp_dir(), 'alice');
    $this->bob = KeyPair::make(key_temp_dir(), 'bob');
});

it('seals for one recipient and opens with their key', function () {
    $paths = [$this->bob->makePublicKeyFile()];
    $plain = 'for bob eyes only';

    [$envKeys, $sealed, $iv] = Envelope::withAlgo()
        ->useCerts($paths)
        ->closeWithIv($plain);

    $bob = Envelope::withAlgo($iv)->usePrivKey($this->bob->privateKey());

    expect($bob->open($envKeys[0], $sealed))->toBe($plain);
});

it('seals once for many recipients with one key each', function () {
    $list = PublicKeyList::make();

    foreach ([$this->alice, $this->bob] as $pair) {
        $list->addKey($pair->publicKey());
    }

    $plain = 'group message';
    [$envKeys, $sealed, $iv] = Envelope::withAlgo()->useKeys($list)->closeWithIv($plain);

    expect($envKeys)->toHaveCount(2);

    foreach ([$this->alice, $this->bob] as $index => $pair) {
        expect(Envelope::withAlgo($iv)->usePrivKey($pair->privateKey())->open($envKeys[$index], $sealed))
            ->toBe($plain);
    }
});

it('closeAllWith reports the generated iv', function () {
    $list = PublicKeyList::make([$this->alice->publicKey()]);

    [$envKeys, $sealed, $iv] = Envelope::closeAllWith($list, 'payload');

    expect($iv)->toBeString()->not->toBeEmpty()
        ->and((string) strlen($iv))->not->toBe('0');
});

it('does not open with the wrong private key', function () {
    $plain = 'targeted';
    [$envKeys, $sealed, $iv] = Envelope::withAlgo()->useCerts([$this->bob->makePublicKeyFile()])->closeWithIv($plain);

    Envelope::withAlgo($iv)->usePrivKey($this->alice->privateKey())->open($envKeys[0], $sealed);
})->throws(RuntimeException::class);