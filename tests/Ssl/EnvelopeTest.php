<?php

use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Config;
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PublicKeyList;
use Strukt\Ssl\FixVector;
use Strukt\Ssl\All;

use PHPUnit\Framework\TestCase;

class EnvelopeTest extends TestCase{

	public function setUp():void{

		//
	}
	public function testSealSingle(){

		$paths[] = sprintf("file://%s/fixture/cacert.pem", getcwd());

		$message = "Hello World!";

		$sealed = All::withEnvl(FixVector::make())->close($paths, $message);

		$this->assertNotNull($sealed[0]);
	}

	public function testSealUnsealMany(){

		// $this->markTestSkipped("@todo:UnsealMany");

		$msg = "Shit is sublime. The combinnation of alliteration and internal rhymes.";

		foreach(range(0,2) as $idx){

			$builder = new KeyPairBuilder(new Config());
			$pubKeys[] = $builder->getPublicKey()->getPem();
			$builders[] = $builder;
		}

		list($keys, $sealed, $iv) = Envelope::closeAllWith(new PublicKeyList($pubKeys), $msg);

		foreach(range(0,2) as $idx){

			$envelope = Envelope::withAlgo($iv)->usePrivKey($builders[$idx]->getPrivateKey());
			$this->assertEquals($msg, $envelope->open($keys[$idx], $sealed));
		}
	}
}