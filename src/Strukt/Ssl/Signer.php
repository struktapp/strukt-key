<?php

namespace Strukt\Ssl;

use Strukt\Contract\KeyPairInterface;

class Signer{

	private $keys;

	public function __construct(KeyPairInterface $keys){

		$this->keys = $keys;
	}

	public function create($data){

		$priKey = $this->keys->getPrivateKey()->getPem();

		openssl_sign($data, $signature, $priKey, OPENSSL_ALGO_SHA256);

		return $signature;
	}

	public static function verify($data, $signature, PublicKey $pubKey){

		$pubKey = $pubKey->getPem();

		$success = openssl_verify($data, $signature, $pubKey, OPENSSL_ALGO_SHA256);

		return $success;
	}
}