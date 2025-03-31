<?php

namespace Strukt\Ssl;

class PublicKeyList{

	private $keys;

	/**
	 * @param array $keyList
	 */
	public function __construct(array $keyList){

		foreach($keyList as $key)
			$this->addKey($key);
	}

	/**
	 * @param array $keyList = []
	 * 
	 * @return static
	 */
	public static function make(array $keyList = []):static{

		return new self($keyList);
	}

	/**
	 * @param mixed $key
	 */
	public function addKey(mixed $key):void{

		$this->keys[] = PublicKey::fromPem($key);
	}

	/**
	 * @return array
	 */
	public function getKeys():array{

		foreach($this->keys as $key)
			$pubKeys[] = $key->getResource();

		return $pubKeys;
	}

	public function freeAll():void{

		// foreach($this->keys as $key)
			// openssl_free_key($key->getResource());
	}
}