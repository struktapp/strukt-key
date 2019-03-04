<?php

use Strukt\Ssl\KeyPair;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Csr\Csr;
use Strukt\Ssl\Csr\UniqueName;
use Strukt\Ssl\Config;

use PHPUnit\Framework\TestCase;

class CsrTest extends TestCase{

	public function setUp(){

		$distgName = new UniqueName(["common"=>"test"]);

		$conf = new Config();

		$this->builder = new KeyPairBuilder($conf);

		$this->csr = new Csr($distgName, $this->builder, $conf);
	}

	public function testSelfSigning(){

		$this->csr->signOwn();

		$cert = $this->csr->getCert();
		$privKey = $this->builder->getPrivateKey()->getPem();

		$this->assertTrue(openssl_x509_check_private_key($cert, $privKey));
	}
}