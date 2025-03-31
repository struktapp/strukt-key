<?php

namespace Strukt;

class Codec{

	/**
	 * @param $iv
	 * @param string $key
	 * @param string $cipher
	 */
	public function __construct($iv, string $key, string $cipher = "AES-128-CBC"){

		$this->cipher = $cipher;
		$this->key = $key;
		$this->options = 0;
		$this->iv = $iv;
	}

	/**
	 * @param $iv
	 * @param string $key
	 * @param string $cipher
	 * 
	 * @return static
	 */
	public static function make($iv, string $key, string $cipher = "AES-128-CBC"):static{

		return new self($iv, $key, $cipher);
	}

	/**
	 * @param string $data
	 * 
	 * @return string|false
	 */
	public function encode(string $data):string|false{

		$encrypted = openssl_encrypt($data, $this->cipher, $this->key, $this->options, $this->iv);

		return $encrypted;
	}

	/**
	 * @param string $encrypted
	 * 
	 * @return string|false
	 */
	public function decode(string $encrypted):string|false{

		$decrypted = openssl_decrypt($encrypted, $this->cipher, $this->key, $this->options, $this->iv);

		return $decrypted;
	}
}