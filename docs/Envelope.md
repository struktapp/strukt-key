```php
// data to encrypt
$data = "This is a long string or other bit of data that i want to encrypt";

// ==== ENCRYPT ====

// read public key
$publicKey =  file_get_contents("fixture/pitsolu.pub");
$publicKey = openssl_get_publickey($publicKey);

// encrypt data using public key into $sealed
$plaintext = 'plaintext';
$cipher = "AES-128-CBC";
$ivlen = openssl_cipher_iv_length($cipher);
$iv = openssl_random_pseudo_bytes($ivlen);

openssl_seal($plaintext, $sealed, $ekeys, array($publicKey), $cipher, $iv);
openssl_free_key($publicKey);

// ==== DECRYPT ====

// get private key to decrypt with
$privateKey = file_get_contents("fixture/pitsolu");
$privateKey = openssl_get_privatekey($privateKey);

// $publicKey, $privateKey are OpenSSL Key resources.
$envkey = $ekeys[0];
openssl_open($sealed, $output, $envkey, $privateKey, $cipher, $iv);
print_r(array($output));
```