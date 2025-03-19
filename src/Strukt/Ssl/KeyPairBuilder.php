<?php

namespace Strukt\Ssl;

use Strukt\Contract\AbstractKeyPair;

class KeyPairBuilder extends AbstractKeyPair{

	protected $conf;

	public function __construct(Config $conf = null, $pass = ""){

		$this->conf = $conf;

		if(is_null($conf))
			$this->conf = new Config();

		$this->privateKey = PrivateKeyBuilder::fromConfig($this->conf, $pass);
	}
}