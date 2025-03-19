<?php

namespace Strukt\Ssl;

use Strukt\Contract\KeyPairInterface;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\KeyPair;
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

	public function __construct(KeyPairInterface $keys){

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

	public function getKeys():KeyPairInterface{

		return $this->keys;
	}

	/**
	* Envelope
	*/
	public static function withEnvl($iv, PrivateKey $privKey = null){


		return new class($iv, $privKey){

			private $privKey;
			private $iv;

			public function __construct($iv, $privKey){

				$this->privKey = $privKey;
				$this->iv = $iv;
			}

			public function close(array $paths, string $message){

				return Envelope::withAlgo($this->iv)->useCerts($paths)->close($message);
			}

			public function open($envKey, $sealed){

				return Envelope::withAlgo($this->iv)->usePrivKey($this->privKey)->open($envKey, $sealed);
			}
		};
	}

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

			public function verify($cert = null){

				if(is_null($cert))
					$cert = $this->getCert();

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
			private $cert;

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
			private $cipher;

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