<?php

namespace Strukt\Ssl;

class Envelope{

	public function __construct(KeyPairContract $keys){

		$this->keys = $keys;
	}

	public function open($envKey, $sealed){

		$privKeyRes = $this->keys->getPrivateKey()->getResource();

		openssl_open($sealed, $open, $envKey, $privKeyRes);

		return $open;
	}

	public function close($data){

		$pubKey = $this->keys->getPublicKey()->getPem();

		openssl_seal($data, $sealed, $envKeys, array($pubKey));

		return array($envKeys, $sealed);
	}

	public static function closeWith(PublicKey $pubKey, $data){

		$pubKey = $pubKey->getPem();

		openssl_seal($data, $sealed, $envKeys, array($pubKey));

		$envKey = current($envKeys);

		return array($envKey, $sealed);
	}

	public static function closeAllWith(PublicKeyList $pubKeyList, $data){

		$pubKeys = $pubKeyList->getKeys();

		openssl_seal($data, $sealed, $envKeys, $pubKeys);

		return array($envKeys, $sealed);
	}
}