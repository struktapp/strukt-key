<?php

namespace Strukt\Ssl;

use Strukt\Contract\KeyPairInterface;

class Cipher{

	private $keys;

	/**
	 * @param Strukt\Contract\KeyPairInterface $keys
	 */
	public function __construct(KeyPairInterface $keys){

		$this->keys = $keys;
	}	

	/**
	* Decrypt the data using the private key and store the results in $decrypted
	* 
	* @param string $encrypted
	* 
	* @return mixed
	*/
	public function decrypt(string $encrypted):mixed{

		openssl_private_decrypt($encrypted, $decrypted, $this->keys->getPrivateKey()->getKey());

		return $decrypted;
	}

	/**
	* Encrypt the data to $encrypted using the public key
	* 
	* @param string $data
	* 
	* @return mixed
	*/
	public function encrypt(string $data):mixed{

		openssl_public_encrypt($data, $encrypted, $this->keys->getPublicKey()->getPem());

		return $encrypted;
	}

	/**
	 * @param \Strukt\Ssl\PublicKey $pubKey
	 * @param string $data
	 * 
	 * @return mixed
	 */
	public static function encryptWith(PublicKey $pubKey, string $data):mixed{

		openssl_public_encrypt($data, $encrypted, $pubKey->getPem());

		return $encrypted;
	}
}