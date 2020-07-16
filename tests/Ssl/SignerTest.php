<?php

use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Config;
use Strukt\Ssl\Signer;

use PHPUnit\Framework\TestCase;

class SignerTest extends TestCase{

	public function setUp():void{

		$this->builder = new KeyPairBuilder(new Config());

		$this->signer = new Signer($this->builder);
	}

	public function testSignatureVerify(){

		$msg = "Won't the real slim shady please stand up?";

		$signature = $this->signer->create($msg);

		$pubKey = $this->builder->getPublicKey();

		$this->assertTrue(Signer::verify($msg, $signature, $pubKey) == 1);
	}
}