<?php

namespace Strukt\Contract;

use Strukt\Ssl\PublicKey;

abstract class AbstractKeyPair implements KeyPairInterface{

	protected $privateKey;
	protected $publicKey;

	public function getPrivateKey(){

		return $this->privateKey;
	}

	public function getPublicKey(){

		if(empty($this->publicKey))
			$this->publicKey = $this->privateKey->getPublicKey();

		return $this->publicKey;
	}

	public function setPublicKey(string $key){

		$this->publicKey = PublicKey::fromPem($key);
	}

	public function freeKey(){

		openssl_free_key($this->privateKey->getResource());
	}
}