<?php

namespace Strukt\Contract;

abstract class AbstractKeyPair implements KeyPairInterface{

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