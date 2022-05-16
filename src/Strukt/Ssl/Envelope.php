<?php

namespace Strukt\Ssl;

use Strukt\Raise;

class Envelope{

	public static function withCerts(array $paths){

		foreach($paths as $path)
			$certs[] = Cert::withPath($path);

		return new class($certs){

			private $certs;

			public function __construct(array $certs){

				$this->certs = $certs;
			}

			public function close(string $data){

				foreach($this->certs as $cert)
					$pubKeys[] = $cert->getResource(); 

				// $cipher_algo = "AES256";
				// $iv = openssl_random_pseudo_bytes(32); //The initialization vector.

				$cipher_algo = 'AES-128-CBC';
				$ivlen = openssl_cipher_iv_length($method);

				if(!openssl_seal($data, $sealed, $envKeys, $pubKeys, $cipher_algo, $ivlen))
					new Raise("Unable to seal message!");

				return array($envKeys, $sealed);
			}
		};
	}

	public static function withPrivKey(PrivateKey $privKey){

		$resource = $privKey->getResource();

		return new class($resource){

			private $resource;

			public function __construct($resource){

				$this->resource = $resource;
			}

			public function open($envKey, $sealed){

				// $cipher_algo = "AES256";
				// $iv = openssl_random_pseudo_bytes(32); //The initialization vector.

				$cipher_algo = 'AES-128-CBC';
				$ivlen = openssl_cipher_iv_length($method);

				// if(!openssl_open($sealed, $open, $envKey, $this->resource));
				if(!openssl_open($sealed, $open, $envKey, $this->resource, $cipher_algo, $ivlen))
					new Raise("Unable to open message!");

				return $open;
			}
		};
	}

	// public static function closeWith(PublicKey $pubKey, $data){

	// 	$pubKey = $pubKey->getResource();

	// 	openssl_seal($data, $sealed, $envKeys, array($this->pubKey));

	// 	return array($envKeys, $sealed);
	// }

	// public static function closeAllWith(PublicKeyList $pubKeyList, $data){

	// 	$pubKeys = $pubKeyList->getKeys();

	// 	openssl_seal($data, $sealed, $envKeys, $pubKeys);

	// 	return array($envKeys, $sealed);
	// }
}