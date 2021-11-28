Crypt
=====

## Installation

### Composer

Create `composer.json` script with contents below then run `composer update`

```js
{
    "require":{

        "strukt/key":"dev-master"
    },
    "minimum-stability":"dev"
}
```

## Hashing

### Bcrypt

```php
$bcrypt = new Strukt\Hash\Bcrypt(12);
$hash = $bcrypt->makeHash('p@55w0rd');
$bcrypt->verify('p@55w0rd', $hash);
```

### Sha256 (Doubled)

```php
$hash = Strukt\Hash\Sha::dbl256('p@55w0rd');
```

## Public & Private Keys

### Generate Keys

```php
$file = "file:///home/churchill/.ssh/id_rsa"
// $keys = new Strukt\Ssl\KeyPair($file, "p@55w0rd");
$keys = new Strukt\Ssl\KeyPair($file);
$pubKey = $keys->getPublicKey();// Strukt\Ssl\PublicKey
$privKey = $keys->getPrivateKey();// Strukt\Ssl\PrivateKey


$builder = new Strukt\Ssl\KeyPairBuilder(new Strukt\Ssl\Config());
$pubKey = $builder->getPublicKey();// Strukt\Ssl\PublicKey
$privKey = $builder->getPrivateKey();// Strukt\Ssl\PrivateKey
```

### Encryp & Decrypt

```php
$message = "Hi! My name is (what?)
My name is (who?)
My name is
Slim Shady
Hi! My name is (huh?)
My name is (what?)
My name is
Slim Shady";

$encrypted = Strukt\Ssl\Cipher::encryptWith($builder->getPublicKey(), $message);

$cipher = new Strukt\Ssl\Cipher($builder);
$decrypted = $cipher->decrypt($encrypted);

$builder->freeKey();
```

## Certificate Signing Request (CSR)

### Self Signed CSR

Generate or get a self signed certificate

```php
$distgName = new Strukt\Ssl\Csr\UniqueName(["common"=>"test"]);
$conf = new Strukt\Ssl\Config();

$keyBuilder = new Strukt\Ssl\KeyPairBuilder($conf);
$csrBuilder = new Strukt\Ssl\Csr\CsrBuilder($distgName, $keyBuilder, $conf);

$request = $csrBuilder->getCsr(); //Strukt\Ssl\Csr\Csr

$privKey = $keyBuilder->getPrivateKey(); //Strukt\Ssl\PrivateKey

$cert = $privKey->getSelfSignedCert($request); //string

Strukt\Ssl\Csr\Csr::verifyCert($privKey, $cert);//boolean
```