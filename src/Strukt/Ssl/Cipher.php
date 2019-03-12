<?php

namespace Strukt\Ssl;

class Cipher{

	private $keys;

	public function __construct(KeyPairContract $keys){

		$this->keys = $keys;
	}	

	/**
	* Decrypt the data using the private key and store the results in $decrypted
	*/
	public function decrypt($encrypted){

		openssl_private_decrypt($encrypted, $decrypted, $this->keys->getPrivateKey()->getResource());

		return $decrypted;
	}

	/**
	* Encrypt the data to $encrypted using the public key
	*/
	public function encrypt($data){

		openssl_public_encrypt($data, $encrypted, $this->keys->getPublicKey()->getPem());

		return $encrypted;
	}

	public static function encryptWith(PublicKey $pubKey, $data){

		openssl_public_encrypt($data, $encrypted, $pubKey->getPem());

		return $encrypted;
	}
}