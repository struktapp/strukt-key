<?php

namespace Strukt\Ssl;

use Strukt\Contract\KeyPairInterface;

class Signer{

	private $keys;

	/**
	 * @param \Strukt\Contract\KeyPairInterface $keys
	 */
	public function __construct(KeyPairInterface $keys){

		$this->keys = $keys;
	}

	/**
	 * @param string $data
	 * 
	 * @return mixed
	 */
	public function create(string $data):mixed{

		$priKey = $this->keys->getPrivateKey()->getPem();

		openssl_sign($data, $signature, $priKey, OPENSSL_ALGO_SHA256);

		return $signature;
	}

	/**
	 * @param string $data
	 * @param string $signature
	 * @param \Strukt\Ssl\PublicKey $pubKey
	 * 
	 * @return bool
	 */
	public static function verify(string $data, string $signature, PublicKey $pubKey):bool{

		$pubKey = $pubKey->getPem();

		$success = openssl_verify($data, $signature, $pubKey, OPENSSL_ALGO_SHA256);

		return $success;
	}
}