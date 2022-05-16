<?php

namespace Strukt\Ssl;

use Strukt\Raise;
use Strukt\Ssl\PublicKey;

class Envelope{

	private $cipher;
	private $iv;

	public function __construct($cipher){

		$this->cipher = $cipher;
		$ivlen = openssl_cipher_iv_length($cipher);
		$this->iv = openssl_random_pseudo_bytes($ivlen);
	}

	public static function withAlgo($cipher = "AES-128-CBC"){

		return new self($cipher);
	}

	public function useCerts(array $paths){

		foreach($paths as $path)
			$certs[] = Cert::withPath($path);

		// print_r($certs[0]->getResource());

		return new class($certs, $this->cipher, $this->iv){

			private $certs;
			private $cipher;
			private $iv;

			public function __construct(array $certs, string $cipher, $iv){

				$this->certs = $certs;
				$this->cipher = $cipher;
				$this->iv = $iv;
			}

			public function close(string $data){

				foreach($this->certs as $cert){

					$pubKey = $cert->extractPublicKey();
					$pubKeys[] = $pubKey->getResource();
				}

				// if(!
				openssl_seal($data, $sealed, $envKeys, $pubKeys, $this->cipher, $this->iv);//)
					// new Raise("Unable to seal message!");

				$eKeys = [];
				foreach($envKeys as $envKey)
					$eKeys[] = base64_encode($envKey);

				return array($eKeys, base64_encode($sealed));
			}
		};
	}

	public function usePrivKey(PrivateKey $privKey){

		$resource = $privKey->getResource();

		return new class($resource, $this->cipher, $this->iv){

			private $resource;
			private $cipher;
			private $iv;

			public function __construct($resource, string $cipher, $iv){

				$this->resource = $resource;
				$this->cipher = $cipher;
				$this->iv = $iv;
			}

			public function open($envKey, $sealed){

				$envKey = base64_decode($envKey);
				$sealed = base64_decode($sealed);

				// if(!
					openssl_open($sealed, $open, $envKey, 
								$this->resource, 
								$this->cipher, 
								$this->iv);//)
					// new Raise("Unable to open message!");

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