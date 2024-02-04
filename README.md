Crypt
=====

## Installation

### Composer

Create `composer.json` script with contents below then run `composer update`

```js
{
    "require":{

        "strukt/key":"v1.1.0-alpha"
    },
    "minimum-stability":"dev"
}
```

## Hashing

### Bcrypt

```php
$hash = bcry("p@55w0rd")->encode()
$success = bcry("p@55w0rd")->verify($hash);
```

### Sha256 (Doubled)

```php
$hash = sha256dbl('p@55w0rd');
```

## Public & Private Keys

## Auto generate keys

```php
$k = Strukt\Ssl\All::makeKeys()
$k->getKeys()->getPrivateKey()->getPem()//get private key
$k->getKeys()->getPublicKey()->getPem()//get public key
$c = $k->useCipher()
$enc = $c->encrypt("p@55w0rd")
$dec = $c->decrypt($enc)
```

### Use existing key

You can generate your key via `ssh-keygen` if you wantta.

```php
$file = "file:///home/churchill/.ssh/id_rsa"
$k = Strukt\Ssl\All::keyPath($file)
```

### Encrypt message with public key

```php
$message = "Hi! My name is (what?)
My name is (who?)
My name is
Slim Shady
Hi! My name is (huh?)
My name is (what?)
My name is
Slim Shady";

$file = "file:///home/churchill/.ssh/id_rsa.pub"

$p = new Strukt\Ssl\KeyPair();//No private key
$p->setPublicKey($file);

$enc = Strukt\Ssl\All::useKeys($p)->toSend($message);
```

### Encrypt with password

```php
$p = new Strukt\Ssl\KeyPair($path, "p@55w0rd");
$p->getPublicKey()//trigger public key extraction from private key

$k = Strukt\Ssl\All::useKeys($p)
```

## Certificate Signing Request (CSR)

### Sign & verify certificate

```php
$kpath = "file:///home/churchill/.ssh/id_rsa"
$cpath = "file:///home/churchill/.ssh/cacert.pem"

$oCsr = Strukt\Ssl\All::keyPath($kpath)->withCert($cpath);

$cert = $oCsr->sign();

$success = $oCsr->verify($cert);
```