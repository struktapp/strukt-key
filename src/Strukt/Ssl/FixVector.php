<?php

namespace Strukt\Ssl;

class FixVector{

	/**
	 * @param string $cipher
	 * 
	 * @return string
	 */
	public static function make(string $cipher = "AES-128-CBC"):string{

		$ivlen = openssl_cipher_iv_length($cipher);
		$iv = openssl_random_pseudo_bytes($ivlen);

		return $iv;
	}
}