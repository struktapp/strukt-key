<?php

use PHPUnit\Framework\TestCase;

use Strukt\Ssl\All;

class CsrTest extends TestCase{

	public function setUp():void{

		//
	}

	// public function testSelfSigningAndVerification():Csr{
	public function testSelfSigningAndVerification(){

		$oCsr = All::makeKeys()->useCsr();

		// $request = $oCsr->getCsr();

		$xCert = $oCsr->selfSign()->getXCert();

		$this->assertTrue($oCsr->verify($xCert));

		// return $request;
	}

	/**
	* @/depends testSelfSigningAndVerification
	*/
	public function testSigningAndVerification(){
	// public function testSigningAndVerification(Csr $request){

		$kpath = sprintf("file://%s/fixture/pitsolu", getcwd());
		$cpath = sprintf("file://%s/fixture/cacert.pem", getcwd());

		$oCsr = All::keyPath($kpath)->withCert($cpath);

		$cert = $oCsr->sign();

		$this->assertTrue($oCsr->verify($cert));
	}
}