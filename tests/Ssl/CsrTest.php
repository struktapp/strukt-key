<?php

use Strukt\Ssl\KeyPair;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Csr\CsrBuilder;
use Strukt\Ssl\Csr\Csr;
use Strukt\Ssl\Csr\UniqueName;
use Strukt\Ssl\Config;

use PHPUnit\Framework\TestCase;

class CsrTest extends TestCase{

	public function setUp():void{

		$distgName = new UniqueName(["common"=>"test"]);
		$conf = new Config();

		$this->keyBuilder = new KeyPairBuilder($conf); 
		$this->csrBuilder = new CsrBuilder($distgName, $this->keyBuilder, $conf);
	}

	public function testSelfSigningAndVerification():Csr{

		$request = $this->csrBuilder->getCsr();

		$privKey = $this->keyBuilder->getPrivateKey();

		$cert = $privKey->getSelfSignedCert($request);

		$request->setCert($cert);

		$this->assertTrue(Csr::verifyCert($privKey, $cert));

		return $request;
	}

	/**
	* @depends testSelfSigningAndVerification
	*/
	public function testSigningAndVerification(Csr $request){

		// $this->markTestSkipped('There is a problem here and no one knows why!');

		$otherKeyBuilder = new KeyPairBuilder(new Config());
		// $otherKeyBuilder = new KeyPairBuilder();
		$privKey = $otherKeyBuilder->getPrivateKey();

		$cert = Csr::sign($request, $privKey);

		print_r($cert);
		print_r(openssl_error_string());

		// $this->assertFalse(Csr::verifyCert($privKey, $request->getCert()));
		$this->assertTrue(Csr::verifyCert($privKey, $cert));

		// Show any errors that occurred here
		print_r(openssl_error_string());
	}
}