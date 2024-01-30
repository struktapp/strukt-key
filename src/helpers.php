<?php

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