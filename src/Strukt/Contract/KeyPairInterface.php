<?php

namespace Strukt\Contract;

use Strukt\Ssl\PublicKey;
use Strukt\Ssl\PrivateKey;

interface KeyPairInterface{

	public function getPrivateKey():PrivateKey;
	public function getPublicKey():PublicKey;

}