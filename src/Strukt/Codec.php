<?php

namespace Strukt;

class Codec{

	public function __construct($iv, string $key, string $cipher = "AES-128-CBC"){

		$this->cipher = $cipher;
		$this->key = $key;
		$this->options = 0;
		$this->iv = $iv;
	}

	public static function make($iv, string $key, string $cipher = "AES-128-CBC"){

		return new self($iv, $key, $cipher);
	}

	public function encode($data){

		$encrypted = openssl_encrypt($data, $this->cipher, $this->key, $this->options, $this->iv);

		return $encrypted;
	}

	public function decode($encrypted){

		$decrypted = openssl_decrypt($encrypted, $this->cipher, $this->key, $this->options, $this->iv);

		return $decrypted;
	}
}