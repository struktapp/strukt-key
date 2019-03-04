<?php

use Strukt\Hash\Sha;
use PHPUnit\Framework\TestCase;

class CryptTest extends TestCase{

	public function testDoubleSha256(){

		$hash = hash("sha256", hash("sha256", "p@55w0rd"));

		$this->assertEquals($hash, Sha::dbl256("p@55w0rd"));
	}
}