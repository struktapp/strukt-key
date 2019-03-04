<?php

namespace Strukt\Ssl;

class PrivateKeyBuilder{

	public static function fromPem($keyOrPemFile, $pass = ""):PrivateKey{

		$key = new PrivateKey(openssl_pkey_get_private($keyOrPemFile, $pass));

		if(!empty($pass))
			$key->withPass($pass);

		return $key;
	}

	public static function fromConfig(Config $conf, $pass = null):PrivateKey{

		$confList = $conf->getAll();

		$key = new PrivateKey(openssl_pkey_new($confList), $pass);
		$key->withConf($conf);

		if(!empty($pass))
			$key->withPass($pass);

		return $key;
	}
}