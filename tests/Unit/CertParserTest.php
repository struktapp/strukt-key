<?php

use Strukt\Ssl\Certificate\Parser;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\Request;
use Strukt\Ssl\Csr\UniqueName;

beforeEach(function () {
    $this->dir = key_temp_dir();
    $this->pair = KeyPair::make($this->dir, 'ca');

    $request = new Request($this->pair, new UniqueName(['common' => 'strukt.example']));
    $request->selfSign();
    $this->certPath = $this->dir . 'cert.pem';
    file_put_contents($this->certPath, $request->getCert());
});

it('parses the subject domain and issuer', function () {
    $parser = new Parser(file_get_contents($this->certPath));

    expect($parser->getDomain())->toBe('strukt.example')
        ->and($parser->getIssuer())->toBe('strukt.example')
        ->and($parser->isSelfSigned())->toBeTrue()
        ->and($parser->isPreCertificate())->toBeFalse()
        ->and($parser->getSignatureAlgo())->not->toBeNull();
});

it('returns real booleans instead of strings', function () {
    $parser = new Parser(file_get_contents($this->certPath));

    expect($parser->isExpired())->toBeBool()
        ->and($parser->isSelfSigned())->toBeBool()
        ->and($parser->isPreCertificate())->toBeBool();
});

it('reports validity windows', function () {
    $parser = new Parser(file_get_contents($this->certPath));

    expect($parser->getFromDate())->toBeInstanceOf(\DateTime::class)
        ->and($parser->getToDate() > $parser->getFromDate())->toBeTrue();
});

it('exposes fingerprint and public key', function () {
    $parser = new Parser(file_get_contents($this->certPath));

    expect($parser->getFingerPrint())->toBe(openssl_x509_fingerprint(file_get_contents($this->certPath)))
        ->and($parser->getPublicKey()->toString())
        ->toBe($this->pair->publicKey()->toString());
});