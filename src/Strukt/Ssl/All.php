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
use Strukt\Ssl\PrivateKey;
use OpenSSLCertificate as SslCert;

class All{

	private $keys;
	private static $config;

	/**
	 * @param \Strukt\Contract\KeyPairInterface $keys
	 */
	public function __construct(KeyPairInterface $keys){

		$this->keys = $keys;
	}

	/**
	 * @return static
	 */
	public static function makeKeys():static{

		return new self(new KeyPairBuilder());
	}

	/**
	* @param \Strukt\Ssl\KeyPair $keys - Private Key Path
	* 
	* @return static
	*/
	public static function useKeys(KeyPair $keys):static{

		return new self($keys);
	}

	/**
	* Generate keys from private key
	*
	* @param string $path - Private Key Path
	* 
	* @return static
	*/
	public static function keyPath(string $path):static{

		return static::useKeys(new KeyPair($path));
	}

	/**
	 * @param ?\Strukt\Ssl\Config $config
	 * 
	 * @return static
	 */
	public static function makeKeysByCfg(?Config $config = null):static{

		if(is_null($config))
			static::$config = new Config;

		return new self(new KeyPairBuilder(static::$config));
	}

	/**
	 * @return \Strukt\Contract\KeyPairInterface
	 */
	public function getKeys():KeyPairInterface{

		return $this->keys;
	}

	/**
	* Envelope
	* 
	* @param $iv
	* @param ?\Strukt\Ssl\PrivateKey $privKey
	* 
	* @return object
	*/
	public static function withEnvl($iv, ?PrivateKey $privKey = null){

		return new class($iv, $privKey){

			private $privKey;
			private $iv;

			/**
			 * @param $iv
			 * @param ?\Strukt\Ssl\PrivateKey $privKey
			 */
			public function __construct($iv, $privKey){

				$this->privKey = $privKey;
				$this->iv = $iv;
			}

			/**
			 * @param array $paths
			 * @param string $message
			 * 
			 * @return array
			 */
			public function close(array $paths, string $message):array{

				return Envelope::withAlgo($this->iv)->useCerts($paths)->close($message);
			}

			/**
			 * @param string $envKey
			 * @param string $sealed
			 * 
			 * @return mixed
			 */
			public function open(string $envKey, string $sealed):mixed{

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

			/**
			 * @param object $oCsr
			 * @param \Strukt\Ssl\Csr\Csr $request
			 * @param \Strukt\Contract\KeyPairInterface $keys
			 */
			public function __construct(object $oCsr, Csr $request, KeyPairInterface $keys){

				$this->request = $request;
				$this->keys = $keys;
				$this->oCsr = $oCsr;
			}

			public function getCert(){

				return $this->request->getCert();
			}

			/**
			 * @return \OpenSSLCertificate|false
			 */
			public function sign():SslCert|false{

				$cert = Csr::sign($this->request, $this->keys->getPrivateKey());

				return $cert;
			}

			/**
			 * @param \OpenSSLCertificate|string $cert
			 * 
			 * @return bool
			 */
			public function verify(SslCert|string|null $cert = null):bool{

				if(is_null($cert))
					$cert = $this->getCert();

				return Csr::verifyCert($this->keys->getPrivateKey(), $cert);
			}
		};
	}

	/**
	* Cert
	* 
	* @param array $names
	* 
	* @return object
	*/
	public function useCsr(array $names = ["common"=>"test"]):object{

		$distgName = new UniqueName($names);

		return new class($distgName, $this->keys, static::$config){

			private $keys;
			private $csrb;
			private $csr;
			private $cert;

			/**
			 * @param \Strukt\Ssl\Csr\UniqueName $distgName
			 * @param \Strukt\Contract'KeyPairInterface $keys
			 * @param ?\Strukt\Ssl\Config $config
			 */
			public function __construct(UniqueName $distgName, KeyPairInterface $keys, ?Config $config){

				$this->keys = $keys;

				$this->csrb = new CsrBuilder($distgName, $keys, $config);

				$this->csr = $this->csrb->getCsr();
			}

			/**
			 * @return \Strukt\Ssl\Csr\Csr
			 */
			public function getCsr():Csr{

				return $this->csr;
			}

			/**
			 * @return \OpenSSLCertificate|false
			 */
			public function getXCert():SslCert|false{

				return $this->cert;
			}

			/**
			 * @return mixed
			 */
			public function getCert():mixed{

				$this->csr->exportCert($this->getXCert());

				return $this->csr->getCert();
			}

			/**
			 * @return static
			 */
			public function selfSign():static{

				$prKey = $this->keys->getPrivateKey();

				$this->cert = $prKey->getSelfSignedCert($this->getCsr());

				return $this;
			}

			/**
			 * @param OpenSSLCertificate|string $cert
			 * 
			 * @return bool
			 */
			public function verify(SslCert|string $cert):bool{

				return Csr::verifyCert($this->keys->getPrivateKey(), $cert);
			}
		};
	}

	/**
	* Cipher
	* 
	* @return object
	*/
	public function useCipher(){

		return new class($this->keys){

			private $keys;
			private $cipher;

			/**
			 * @param Strukt\Contract\KeyPairInterface $keys
			 */
			public function __construct(KeyPairInterface $keys){

				$this->cipher = new Cipher($keys);
			}

			/**
			 * @param string $message
			 * 
			 * @return mixed
			 */
			public function encrypt(string $message):mixed{

				return $this->cipher->encrypt($message);
			}

			/**
			 * @param string $enc_msg
			 * 
			 * @return mixed
			 */
			public function decrypt(string $enc_msg):mixed{

				return $this->cipher->decrypt($enc_msg);
			}
		};
	}

	/**
	* Cipher
	* 
	* @param string $message
	* 
	* @return mixed
	*/
	public function toSend(string $message):mixed{

		return Cipher::encryptWith($this->keys->getPublicKey(), $message);
	}
}