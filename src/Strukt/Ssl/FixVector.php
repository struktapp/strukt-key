<?php

namespace Strukt\Ssl;

class FixVector{

	public static function make(string $cipher = "AES-128-CBC"){

		$ivlen = openssl_cipher_iv_length($cipher);
		$iv = openssl_random_pseudo_bytes($ivlen);

		return $iv;
	}
}