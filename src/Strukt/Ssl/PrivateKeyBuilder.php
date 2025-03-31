<?php

namespace Strukt\Ssl;

class PrivateKeyBuilder{

	/**
	 * @param keyOrPemFile
	 * @param string $pass
	 * 
	 * @return \Strukt\Ssl\PrivateKey
	 */
	public static function fromPem($keyOrPemFile, string $pass = ""):PrivateKey{

		$key = new PrivateKey(openssl_pkey_get_private($keyOrPemFile, $pass));

		if(!empty($pass))
			$key->withPass($pass);

		return $key;
	}

	/**
	 * @param \Strukt\Ssl\Config $conf
	 * @param ?string $pass
	 * 
	 * @return \Strukt\Ssl\PrivateKey
	 */
	public static function fromConfig(Config $conf, ?string $pass = null):PrivateKey{

		$confList = $conf->getAll();

		$key = new PrivateKey(openssl_pkey_new($confList), $pass);
		$key->withConf($conf);

		if(!empty($pass))
			$key->withPass($pass);

		return $key;
	}
}