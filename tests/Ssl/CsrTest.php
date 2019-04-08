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
		$this->request = new Csr($distgName, $this->builder, $conf);
	}

	public function testSelfSigningAndVerification(){

		$this->request->signOwn();

		$crt = $this->request->getCert();
		$csr = $this->request->getCsr();
		$privKey = $this->builder->getPrivateKey();

		$this->assertTrue(Csr::verifyCert($privKey, $crt));

		// return array($csr, $crt);
	}

	/**
	// @depends testSelfSigningAndVerification
	*/
	// public function testSigningAndVerification($csr, $crt){

	// 	$this->markTestSkipped('There is a problem here and no one knows why!');

	// 	$distgName = new UniqueName(["common"=>"test"]);
	// 	$conf = new Config();
	// 	$builder = new KeyPairBuilder($conf);
	// 	$req = new Csr($distgName, $builder, $conf);

	// 	$req->sign($csr, $crt);

	// 	$cert = $req->getCert();

	// 	$privKey = $builder->getPrivateKey();

	// 	$this->assertTrue(Csr::verifyCert($privKey, $cert));
	// }
}