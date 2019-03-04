<?php

namespace Strukt\Ssl;

interface KeyPairContract{

	public function getPrivateKey();
	public function getPublicKey();

}