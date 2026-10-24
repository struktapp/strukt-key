<?php

use Strukt\Ssl\Cert;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\Request;
use Strukt\Ssl\Csr\UniqueName;

beforeEach(function () {
    $this->pair = KeyPair::make(key_temp_dir(), 'ca');
    $this->names = ['common' => 'strukt.example', 'org' => 'Strukt', 'country' => 'KE'];
});

it('builds a csr with the subject fields', function () {
    $request = new Request($this->pair, new UniqueName($this->names));

    $subject = $request->getCsr()->getSubject();

    expect($subject['CN'])->toBe('strukt.example')
        ->and($subject['O'])->toBe('Strukt')
        ->and($subject['C'])->toBe('KE');
});

it('self-signs a certificate the pair can verify', function () {
    $request = new Request($this->pair, new UniqueName($this->names));

    $request->selfSign();

    expect($request->getCert())->toContain('BEGIN CERTIFICATE')
        ->and($request->verify())->toBeTrue();
});

it('exposes a parsed certificate', function () {
    $request = new Request($this->pair, new UniqueName(['common' => 'strukt.example']));
    $request->selfSign();

    $parsed = $request->getCsr()->parse();

    expect($parsed['subject']['CN'])->toBe('strukt.example');
});

it('unique name expands the friendly aliases', function () {
    $unique = new UniqueName(['common' => 'x', 'orgUnit' => 'eng', 'loc' => 'Nairobi']);

    expect($unique->getDetails())->toBe([
        'stateOrProvinceName' => 'Nairobi',
        'organizationalUnitName' => 'eng',
        'commonName' => 'x',
    ])->and($unique->get('common'))->toBe('x');
});

it('imports a certificate from disk and verifies it', function () {
    $certDir = key_temp_dir();
    $certPath = $certDir . 'ca.pem';

    $request = new Request($this->pair, new UniqueName(['common' => 'ca.example']));
    $request->selfSign();
    file_put_contents($certPath, $request->getCert());

    $adopted = (new Request($this->pair, new UniqueName(['common' => 'x'])))->importCert($certPath);

    expect($adopted->verify())->toBeTrue()
        ->and($adopted->getCert())->toContain('BEGIN CERTIFICATE');
});

it('cert extract matches the public key used for sealing', function () {
    $certDir = key_temp_dir();
    $certPath = $certDir . 'ca.pem';

    $request = new Request($this->pair, new UniqueName(['common' => 'ca.example']));
    $request->selfSign();
    file_put_contents($certPath, $request->getCert());

    $publicKey = Cert::withPath($certPath)->extractPublicKey();

    expect($publicKey->toString())->toBe($this->pair->publicKey()->toString());
});