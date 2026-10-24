<?php

/** Coverage for the command line front end. */

use Strukt\Key\Cli\Application;

/**
 * Runs a command and captures what it writes to standard output.
 *
 * @param list<string> $arguments Command arguments.
 * @return string Captured output.
 */
function kcli(array $arguments): string
{
    return kcliRun($arguments)['output'];
}

/**
 * Runs a command and reports both its exit code and output.
 *
 * @param list<string> $arguments Command arguments.
 * @return array{status: int, output: string} Exit code and captured output.
 */
function kcliRun(array $arguments): array
{
    ob_start();

    try {
        $status = (new Application())->run(array_merge(['kcli'], $arguments));
    } finally {
        $output = (string) ob_get_clean();
    }

    return ['status' => $status, 'output' => $output];
}

it('no arguments lists the available commands', function () {
    expect(kcli([]))->toContain('Available commands:')
        ->and(kcli(['--help']))->toContain('Available commands:')
        ->and(kcli(['-h']))->toContain('Available commands:');
});

it('reports the version', function () {
    expect(kcli(['version']))->toContain('version: 0.1.0')
        ->and(kcli(['version', '--json']))->toContain('"version": "0.1.0"');
});

it('hashes input', function () {
    $output = kcli(['hash', 'abc']);

    expect($output)->toContain('hash: ' . hash('sha256', 'abc'))
        ->and(kcli(['hash', 'abc', '--type', 'sha256dbl']))->toContain(hash('sha256', hash('sha256', 'abc')));
});

it('hashes and checks a password', function () {
    $hash = trim(kcli(['bcrypt', 'secret', '--json']));
    $hash = json_decode($hash, true)['hash'];

    expect(trim($hash))->toStartWith('$2')
        ->and(kcliRun(['bcrypt:check', 'secret', $hash])['status'])->toBe(0)
        ->and(kcliRun(['bcrypt:check', 'wrong', $hash])['status'])->toBe(1);
});

it('generates a key pair and re-reads it', function () {
    $dir = key_temp_dir();

    $run = kcliRun(['keys:new', '--dir', $dir, '--name', 'alice']);

    expect($run['status'])->toBe(0)
        ->and($run['output'])->toContain('private')
        ->and(is_file($dir . 'alice.pem'))->toBeTrue()
        ->and(is_file($dir . 'alice.pub.pem'))->toBeTrue();
});

it('sign and verify round trip through files', function () {
    $dir = key_temp_dir();
    kcliRun(['keys:new', '--dir', $dir, '--name', 'alice']);

    $sign = kcliRun(['sign', 'hello', '--key', $dir . 'alice.pem', '--json']);
    $signature = json_decode($sign['output'], true)['signature'];

    expect(kcliRun(['verify', 'hello', $signature, '--key', $dir . 'alice.pub.pem'])['status'])->toBe(0)
        ->and(kcli(['verify', 'hello', $signature, '--key', $dir . 'alice.pub.pem', '--json']))->toContain('"valid": true');
});

it('encrypts and decrypts through the cli', function () {
    $enc = kcliRun(['enc', 'top secret', 'cli-secret', '--json']);
    $payload = json_decode($enc['output'], true);

    expect($payload)->toHaveKey('iv')
        ->and(kcli(['dec', $payload['ciphertext'], 'cli-secret', '--json']))->toContain('top secret');
});

it('self-signs a certificate and reads it back', function () {
    $dir = key_temp_dir();

    kcliRun(['cert:selfsign', '--dir', $dir, '--name', 'web', '--common', 'strukt.example']);

    $info = kcli(['cert:info', $dir . '/' . 'cert.pem', '--json']);

    expect($info)->toContain('strukt.example')
        ->and($info)->toContain('"expired": false');

    $verify = kcliRun(['cert:verify', $dir . '/' . 'cert.pem', '--key', $dir . 'web.pem']);

    expect($verify['status'])->toBe(0);
});

it('seals and opens an envelope through the cli', function () {
    $certDir = key_temp_dir();

    kcliRun(['cert:selfsign', '--dir', $certDir, '--name', 'bob', '--common', 'bob.example']);

    $close = kcliRun([
        'envelope:close',
        'letter',
        $certDir . 'cert.pem',
        '--json',
    ]);
    $closed = json_decode($close['output'], true);

    expect($closed)->toHaveKey('envelope_keys')
        ->and($closed)->toHaveKey('sealed')
        ->and($closed)->toHaveKey('iv');

    $open = kcliRun([
        'envelope:open',
        $closed['envelope_keys'][0],
        $closed['sealed'],
        $closed['iv'],
        '--key',
        $certDir . 'bob.pem',
    ]);

    expect(trim($open['output']))->toBe('letter');
});

it('mints and validates csrf tokens through the cli', function () {
    $token = trim(kcli(['csrf', '{"user":1}', 'c-key', '--json']));
    $token = json_decode($token, true)['token'];

    expect(kcliRun(['csrf:check', $token, 'c-key'])['status'])->toBe(0)
        ->and(kcliRun(['csrf:check', $token, 'wrong'])['status'])->toBe(1);
});

it('mints and validates jwt tokens through the cli', function () {
    $token = trim(kcli(['jwt:encode', '{"role":"admin"}', 'j-secret', '--json']));
    $token = json_decode($token, true)['token'];

    expect(kcliRun(['jwt:decode', $token, 'j-secret'])['status'])->toBe(0)
        ->and(kcliRun(['jwt:decode', $token, 'nope'])['status'])->toBe(1);
});

it('reports an unknown command as an error', function () {
    expect(kcliRun(['nope'])['status'])->not->toBe(0);
});