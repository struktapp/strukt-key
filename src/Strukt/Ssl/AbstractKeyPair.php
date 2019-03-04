<?php

namespace Strukt\Ssl;

abstract class AbstractKeyPair implements KeyPairContract{

	protected $privateKey;
	protected $publicKey;

	public function getPrivateKey(){

		return $this->privateKey;
	}

	public function getPublicKey(){

		return $this->privateKey->getPublicKey();
	}

	public function freeKey(){

		openssl_free_key($this->privateKey->getResource());
	}
}