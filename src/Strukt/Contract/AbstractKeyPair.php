<?php

namespace Strukt\Contract;

use Strukt\Ssl\PublicKey;

abstract class AbstractKeyPair implements KeyPairInterface{

	protected $privateKey;
	protected $publicKey;

	/**
	 * @return \Strukt\Ssl\PrivateKey
	 */
	public function getPrivateKey(){

		return $this->privateKey;
	}

	/**
	 * @return \Strukt\Ssl\PublicKey
	 */
	public function getPublicKey(){

		if(empty($this->publicKey))
			$this->publicKey = $this->privateKey->getPublicKey();

		return $this->publicKey;
	}

	/**
	 * @param string $key
	 * 
	 * @return void
	 */
	public function setPublicKey(string $key):void{

		$this->publicKey = PublicKey::fromPem($key);
	}

	public function freeKey(){

		openssl_free_key($this->privateKey->getResource());
	}
}