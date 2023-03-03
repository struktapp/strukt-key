<?php

namespace Strukt\Ssl;

class PublicKeyList{

	private $keys;

	public function __construct(Array $keyList){

		foreach($keyList as $key)
			$this->addKey($key);
	}

	public static function make(Array $keyList = []){

		return new self($keyList);
	}

	public function addKey($key){

		$this->keys[] = PublicKey::fromPem($key);
	}

	public function getKeys(){

		foreach($this->keys as $key)
			$pubKeys[] = $key->getResource();

		return $pubKeys;
	}

	public function freeAll(){

		foreach($this->keys as $key)
			openssl_free_key($key->getResource());
	}
}