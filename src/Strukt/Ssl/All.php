<?php

namespace Strukt\Ssl;

use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\KeyPairContract;
use Strukt\Ssl\Config;
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PublicKeyList;
use Strukt\Ssl\Cipher;
use Strukt\Ssl\Csr\CsrBuilder;
use Strukt\Ssl\Csr\Csr;
use Strukt\Ssl\Csr\UniqueName;

class All{

	private $keys;
	private static $config;

	public function __construct(KeyPairContract $keys){

		$this->keys = $keys;
	}

	public static function makeKeys(){

		return new self(new KeyPairBuilder());
	}

	public static function useKeys(KeyPair $keys){

		return new self($keys);
	}


	/**
	* Generate keys from private key
	*
	* @param $path Private Key Path
	*/
	public static function keyPath(string $path){

		return static::useKeys(new KeyPair($path));
	}

	public static function makeKeysByCfg(Config $config = null){

		if(is_null($config))
			static::$config = new Config;

		return new self(new KeyPairBuilder(static::$config));
	}

	public function getKeys():KeyPairContract{

		return $this->keys;
	}

	/**
	* Envelope
	*/
	// public function withEnvl(){

	// 	$envelope = new Envelope($this->keys);

	// 	return new class($envelope, $this->keys){

	// 		private $envelope;
	// 		private $keys;

	// 		public function __construct($envelope, $keys){

	// 			$this->keys = $keys;
	// 			$this->envelope = $envelope;
	// 		}

	// 		public function close(string $message){

	// 			$pubKey = $this->keys->getPublicKey();

	// 			list($key, $sealed) = Envelope::closeWith($pubKey, $message);

	// 			return array($key, $sealed);
	// 		}

	// 		public function open($key, $sealed){

	// 			$unseal = $this->envelope->open($key, $sealed);

	// 			return $unseal;
	// 		}
	// 	};
	// }

	/**
	* Cert
	*/
	public function withCert(string $path, array $names = ["common"=>"test"]){

		$oCsr = $this->useCsr($names);
		$request = $oCsr->getCsr();
		$request->exportCert($path);

		return new class($oCsr, $request, $this->keys){

			private $request;
			private $keys;
			private $oCsr;

			public function __construct($oCsr, $request, $keys){

				$this->request = $request;
				$this->keys = $keys;
				$this->oCsr = $oCsr;
			}

			public function getCert(){

				return $this->request->getCert();
			}

			public function sign(){

				$cert = Csr::sign($this->request, $this->keys->getPrivateKey());

				return $cert;
			}

			public function verify($cert){

				return Csr::verifyCert($this->keys->getPrivateKey(), $cert);
			}
		};
	}

	/**
	* Cert
	*/
	public function useCsr(array $names = ["common"=>"test"]){

		$distgName = new UniqueName($names);

		return new class($distgName, $this->keys, static::$config){

			private $keys;
			private $csrb;
			private $csr;

			public function __construct($distgName, $keys, $config){

				$this->keys = $keys;

				$this->csrb = new CsrBuilder($distgName, $keys, $config);

				$this->csr = $this->csrb->getCsr();
			}

			public function getCsr(){

				return $this->csr;
			}

			public function getXCert(){

				return $this->cert;
			}

			public function getCert(){

				$this->csr->exportCert($this->getXCert());

				return $this->csr->getCert();
			}

			public function selfSign(){

				$prKey = $this->keys->getPrivateKey();

				$this->cert = $prKey->getSelfSignedCert($this->getCsr());

				return $this;
			}

			public function verify($cert){

				return Csr::verifyCert($this->keys->getPrivateKey(), $cert);
			}
		};
	}

	/**
	* Cipher
	*/
	public function useCipher(){

		return new class($this->keys){

			private $keys;

			public function __construct($keys){

				$this->cipher = new Cipher($keys);
			}

			public function encrypt(string $message){

				return $this->cipher->encrypt($message);
			}

			public function decrypt($enc_msg){

				return $this->cipher->decrypt($enc_msg);
			}
		};
	}

	/**
	* Cipher
	*/
	public function toSend(string $message){

		return Cipher::encryptWith($this->keys->getPublicKey(), $message);
	}
}