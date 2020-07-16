<?php

use Strukt\Hash\Bcrypt;
use PHPUnit\Framework\TestCase;

class BcryptTest extends TestCase{

	public function setUp():void{

		$this->bcrypt = new Bcrypt(16);
	}

	public function testVerify(){

		$hash = $this->bcrypt->makeHash('p@55w0rd');

		$this->assertTrue($this->bcrypt->verify('p@55w0rd', $hash));
	}
}