<?php

use Strukt\Hash\Bcrypt;
use Strukt\Hash\Sha;
use Strukt\Codec;
use Strukt\Csrf;
use Strukt\Jwt;
use Strukt\Ssl\Config;
use Strukt\Ssl\All;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\KeyPair;
use Strukt\Contract\KeyPairInterface;
use Strukt\Fs;

helper("key");

if(helper_add("codec")){

	/**
	 * @return object
	 */
	function codec():object{

		return new class(){

			private $codec;

			public function __construct(){

				$cipher = config("crypt.algo");
				$vector = hex2bin(config("crypt.vector"));
				$key = config("crypt.key");

				$this->codec = Codec::make($vector, $key, $cipher);
			}

			/**
			 * @param string $data
			 * 
			 * @return mixed
			 */
			public function encode(string $data):mixed{

				return $this->codec->encode($data);
			}

			/**
			 * @param string $encrypted
			 * 
			 * @return mixed
			 */
			public function decode(string $encrypted):mixed{

				return $this->codec->decode($encrypted);
			}
		};
	}
}

if(helper_add("bcry")){

	/**
	 * @param string $passwords
	 * @param integer $rounds = 12
	 * 
	 * @return object
	 */
	function bcry(string $password, int $rounds = 12):object{

		$hash_class = new Bcrypt($rounds);

		return new class($hash_class, $password){

			/**
			 * @param \Strukt\Hash\Bcrypt $hash_class
			 * @param string $password
			 */
			public function __construct(Bcrypt $hash_class, string $password){

				$this->hash_class = $hash_class;
				$this->password = $password;
			}

			/**
			 * @return string
			 */
			public function encode():string{

				return $this->hash_class->makeHash($this->password);
			}

			/**
			 * @param string $hash
			 * 
			 * @return bool
			 */
			public function verify(string $hash):bool{

				return $this->hash_class->verify($this->password, $hash);		
			}
		};
	}
}

if(helper_add("sha256")){

	/**
	 * @param string $whatever
	 * 
	 * @return string
	 */
	function sha256(string $whatever):string{

		return Sha::once256($whatever);
	}
}

if(helper_add("sha256dbl")){

	/**
	 * @param string $whatever
	 * 
	 * @return string
	 */
	function sha256dbl(string $whatever):string{

		return Sha::dbl256($whatever);
	}
}

if(helper_add("csrf")){

	/**
	 * CSRF Token - Cross-domain Request Forgery Token
	 * 
	 * @param array|string $data
	 * 
	 * @return object
	 */
	function csrf(array|string $data):object{

		return new class($data){

			/**
			 * @param array|string $data
			 */
			public function __construct(array|string $data){

				$this->data = $data;
			}

			/**
			 * @return string|false|null
			 */
			public function decode():string|false|null{

				if(is_string($this->data))
					return Csrf::decode($this->data);

				return null;
			}

			/**
			 * @return bool
			 */
			public function valid():bool{

				if(is_string($this->data))
					return Csrf::valid($this->data);

				return false;
			}

			/**
			 * @return string
			 */
			public function encode():string{

				return (string) Csrf::make($this->data, config("csrf.duration"));
			}
		};
	}
}

if(helper_add("jwt")){

	/**
	 * JWT Token - Json Web Token
	 * 
	 * @param array|string $data
	 * 
	 * @return string|object
	 */
	function jwt(array|string $data):string|object{

		$jwt = new Jwt;
		if(is_array($data))
			return $jwt->encode($data);

		if(is_string($data))
			return new class($jwt->decode($data)){

				private $data;

				/**
				 * ?stdClass $data
				 */
				public function __construct(?stdClass $data){

					$this->data = $data;
				}

				/**
				 * @return bool
				 */
				public function valid():bool{

					if(is_null($this->data))
						return false;
					
					return Jwt::valid($this->data);
				}

				/**
				 * @return stdClass
				 */
				public function yield():stdClass{

					return $this->data;
				}
			};
	}
}

if(helper_add("ssl")){

	/**
	 * @param \Strukt\Ssl\Config|
	 * 		  \Strukt\Ssl\KeyPair|
	 * 		  \Strukt\Contract\KeyPairInterface|
	 * 		  \Strukt\Ssl\KeyPair|string|null $keysOrPathOrCfg - can be path
	 * 
	 * @return \Strukt\Ssl\All
	 */
	function ssl(KeyPair|KeyPairInterface|Config|string|null $keysOrPathOrCfg = null):All{

		if(is_string($keysOrPathOrCfg))
			if(Fs::isFile($keysOrPathOrCfg))
				$keysOrPathOrCfg = local($keysOrPathOrCfg);

		if($keysOrPathOrCfg instanceof KeyPair)
			return All::useKeys($keysOrPathOrCfg);

		if($keysOrPathOrCfg instanceof KeyPairInterface)
			return new All($keysOrPathOrCfg);

		if($keysOrPathOrCfg instanceof Config)
			return All::makeKeysByCfg($keysOrPathOrCfg);

		if(is_string($keysOrPathOrCfg))
			return All::keyPath($keysOrPathOrCfg);

		if(is_null($keysOrPathOrCfg))
			return All::makeKeys();
	}
}

if(helper_add("keypair")){

	/**
	 * @param mixed $keyOrPemFile = ""
	 * @param string $pass = ""
	 * 
	 * @return \Strukt\Contract\KeyPairInterface
	 */
	function keypair(mixed $keyOrPemFile="", string $pass=""):KeyPairInterface{

		if(Fs::isFile($keyOrPemFile))
			$keyOrPemFile = local($keyOrPemFile);

		return new KeyPair($keyOrPemFile, $pass);
		
	}
}

if(helper_add("pubkey")){

	/**
	 * Returns Strukt\Ssl\KeyPair without a Private Key
	 *  Alias for: $p = keypair()->setPublicKey($file);
	 * 
	 * @param string $path - local URL to Public Key
	 * 
	 * @return \Strukt\Contract\KeyPairInterface
	 */
	function pubkey(string $path):KeyPairInterface{

		return keypair()->setPublicKey($path);
	}
}