<?php

namespace Strukt\Ssl;

use Strukt\Raise;
use Strukt\Ssl\PublicKey;
use Strukt\Ssl\PrivateKey;
use Strukt\Ssl\FixVector;

class Envelope{

	private $cipher;
	private $iv;

	/**
	 * @param string $cipher
	 * @param $iv
	 */
	public function __construct(string $cipher, $iv){

		$this->cipher = $cipher;
		$this->iv = $iv;
	}

	/**
	 * @param $iv
	 * @param string $cipher
	 * 
	 * @return static
	 */
	public static function withAlgo($iv, string $cipher = "AES-128-CBC"):static{

		return new self($cipher, $iv);
	}

	/**
	 * @param array $paths
	 * 
	 * @return object
	 */
	public function useCerts(array $paths):object{

		$pubKeyLs = PublicKeyList::make();
		foreach($paths as $path)
			$pubKeyLs->addKey(Cert::withPath($path)->extractPublicKey()->getResource());

		return new class($pubKeyLs, $this->cipher, $this->iv){

			private $pubKeyLs;
			private $cipher;
			private $iv;

			/**
			 * @param \Strukt\Ssl\PublicKey $pubKeyLs
			 * @param string $cipher
			 * @param string $iv
			 */
			public function __construct(PublicKeyList $pubKeyLs, string $cipher, $iv){

				$this->pubKeyLs = $pubKeyLs;
				$this->cipher = $cipher;
				$this->iv = $iv;
			}

			/**
			 * @param string $data
			 * 
			 * @return array
			 */
			public function close(string $data):array{

				$pubKeys = $this->pubKeyLs->getKeys();

				if(!openssl_seal($data, $sealed, $envKeys, $pubKeys, $this->cipher, $this->iv))
					new Raise("Unable to seal message!");

				$this->pubKeyLs->freeAll();

				$eKeys = [];
				foreach($envKeys as $envKey)
					$eKeys[] = base64_encode($envKey);

				return array($eKeys, base64_encode($sealed));
			}
		};
	}

	/**
	 * @param \Strukt\Ssl\PrivateKey $privKey
	 * 
	 * @return object
	 */
	public function usePrivKey(PrivateKey $privKey):object{

		$resource = $privKey->getKey();

		return new class($resource, $this->cipher, $this->iv){

			private $resource;
			private $cipher;
			private $iv;

			/**
			 * @param $resource - Private Key
			 * @param string $cipher
			 * @param string $iv
			 */
			public function __construct($resource, string $cipher, $iv){

				$this->resource = $resource;
				$this->cipher = $cipher;
				$this->iv = $iv;
			}

			/**
			 * @param string $envKey
			 * @param string $sealed
			 * 
			 * @return mixed
			 */
			public function open(string $envKey, string $sealed):mixed{


				if(!openssl_open($sealed, $open, $envKey, 
								$this->resource, 
								$this->cipher, 
								$this->iv))
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

	/**
	 * @param \Strukt\Ssl\PublicKeyList $pubKeyList
	 * @param string $data
	 * @param string $cipher
	 * 
	 * @return array
	 */
	public static function closeAllWith(PublicKeyList $pubKeyList, 
											string $data, 
											string $cipher = "AES-128-CBC"):array{

		$pubKeys = $pubKeyList->getKeys();

		$iv = FixVector::make($cipher);

		openssl_seal($data, $sealed, $envKeys, $pubKeys, cipher_algo:$cipher, iv:$iv);

		return array($envKeys, $sealed, $iv);
	}
}