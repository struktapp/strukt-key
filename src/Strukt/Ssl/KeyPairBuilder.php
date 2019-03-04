<?php

namespace Strukt\Ssl;

class KeyPairBuilder extends AbstractKeyPair implements KeyPairContract{

	public function __construct(Config $conf = null, $pass = ""){

		$this->conf = $conf;

		if(is_null($conf))
			$this->conf = new Config();

		$this->privateKey = PrivateKeyBuilder::fromConfig($this->conf, $pass);
	}
}