<?php

helper("key");

if(helper_add("codec")){

	function codec(){

		return new class(){

			public function __construct(){

				$cipher = config("crypt.algo");
				$vector = hex2bin(config("crypt.vector"));
				$key = config("crypt.key");

				$this->codec = \Strukt\Codec::make($vector, $key, $cipher);
			}

			public function encode($data){

				return $this->codec->encode($data);
			}

			public function decode($encrypted){

				return $this->codec->decode($encrypted);
			}
		};
	}
}

if(helper_add("bcry")){

	function bcry(string $password, int $rounds = 12){

		$hash_class = new Strukt\Hash\Bcrypt($rounds);

		return new class($hash_class, $password){

			public function __construct($hash_class, string $password){

				$this->hash_class = $hash_class;
				$this->password = $password;
			}

			public function encode(){

				return $this->hash_class->makeHash($this->password);
			}

			public function verify(string $hash){

				return $this->hash_class->verify($this->password, $hash);		
			}
		};
	}
}

if(helper_add("sha256")){

	function sha256(string $whatever){

		return Strukt\Hash\Sha::once256($whatever);
	}
}

if(helper_add("sha256dbl")){

	function sha256dbl(string $whatever){

		return Strukt\Hash\Sha::dbl256($whatever);
	}
}

if(helper_add("csrf")){

	function csrf(array|string $data){

		return new class($data){

			public function __construct(array|string $data){

				$this->data = $data;
			}

			public function decode(){

				if(is_string($this->data))
					return Strukt\Csrf::decode($this->data);

				return null;
			}

			public function valid(){

				if(is_string($this->data))
					return Strukt\Csrf::valid($this->data);

				return false;
			}

			public function encode(){

				return (string) Strukt\Csrf::make($this->data, config("csrf.duration"));
			}
		};
	}
}

if(helper_add("jwt")){

	function jwt(array|string $data){

		$jwt = new Strukt\Jwt;
		if(is_array($data))
			return $jwt->encode($data);

		if(is_string($data))
			return new class($jwt->decode($data)){

				private $data;

				public function __construct(?stdClass $data){

					$this->data = $data;
				}

				public function valid():bool{

					if(is_null($this->data))
						return false;
					
					return \Strukt\Jwt::valid($this->data);
				}

				public function yield():stdClass{

					return $this->data;
				}
			};
	}
}
