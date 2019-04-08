<?php

use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Config;
use Strukt\Ssl\Envelope;
use Strukt\Ssl\PublicKeyList;

use PHPUnit\Framework\TestCase;

class EnvelopeTest extends TestCase{

	public function setUp(){

		$this->builder = new KeyPairBuilder(new Config());

		$this->envelope = new Envelope($this->builder);
	}

	public function testSingleSealUnseal(){

		$pubKey = $this->builder->getPublicKey();

		$msg = "You better lose yourself in the music, the moment 
				You own it, you better never let it go";

		list($key, $sealed) = Envelope::closeWith($pubKey, $msg);

		$this->assertEquals($msg, $this->envelope->open($key, $sealed));
	}

	public function testSealUnsealMany(){

		$msg = "Shit is sublime. The combinnation of alliteration and internal rhymes.";

		foreach(range(0,2) as $idx){

			$builder = new KeyPairBuilder(new Config());
			$pubKeys[] = $builder->getPublicKey()->getPem();
			$builders[] = $builder;
		}

		list($keys, $sealed) = Envelope::closeAllWith(new PublicKeyList($pubKeys), $msg);

		foreach(range(0,2) as $idx){

			$envelope = new Envelope($builders[$idx]);
			$this->assertEquals($msg, $envelope->open($keys[$idx], $sealed));
		}
	}
}