<?php

namespace Strukt\Ssl;

class Envelope{

	public function __construct(KeyPairContract $keys){

		$this->keys = $keys;
	}

	public function open($envKey, $sealed){

		$privKeyRes = $this->keys->getPrivateKey()->getResource();

		openssl_open($sealed, $open, $envKey, $privKeyRes);

		$this->keys->freeKey();

		return $open;
	}

	public function close($data){

		$pubKey = $this->keys->getPublicKey()->getPem();

		openssl_seal($data, $sealed, $envKey, array($pubKey));

		$this->keys->freeKey();

		return array($envKey, $sealed);
	}

	public static function closeForAll($data, PublicKeyList $pubKeyList){

		$pubKeys = $pubKeyList->getKeys();

		openssl_seal($data, $sealed, $envKeys, $pubKeys);

		$pubKeyList->freeAll();

		return array($envKeys, $sealed);
	}
}