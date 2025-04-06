<?php

namespace Strukt\Contract;

use Strukt\Ssl\PublicKey;
use Strukt\Ssl\PrivateKey;

abstract class AbstractKeyPair implements KeyPairInterface{

	protected $privateKey;
	protected $publicKey;

	/**
	 * @return \Strukt\Ssl\PrivateKey
	 */
	public function getPrivateKey():PrivateKey{

		return $this->privateKey;
	}

	/**
	 * @return \Strukt\Ssl\PublicKey
	 */
	public function getPublicKey():PublicKey{

		if(empty($this->publicKey))
			$this->publicKey = $this->privateKey->getPublicKey();

		return $this->publicKey;
	}

	/**
	 * @param string $key
	 * 
	 * @return static
	 */
	public function setPublicKey(string $key):static{

		$this->publicKey = PublicKey::fromPem($key);

		return $this;
	}

	public function freeKey(){

		openssl_free_key($this->privateKey->getResource());
	}
}