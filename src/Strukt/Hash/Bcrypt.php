<?php

namespace Strukt\Hash;

use Strukt\Util\Str;

/**
@link https://goo.gl/fLtLGn

Bcrypt is designed to be slow...

...because if it takes more time to hash the value, it also takes a much longer time to brute-force the password.

Keep in mind that slow means that it requires more computing power. The same goes for when a potential hacker tries to brute-force a password.

==================================================================================

@link https://goo.gl/pzL7ZF

Have a good look at the values you're dealing with. The random salt generated will be, say:

abcdefg...
What is fed into crypt looks like this:

crypt($password, '$2y$10$abcdefg...')
                   |  |    |
                   |  |    +- the salt
                   |  +- the cost parameter
                   +- the algorithm type
The result looks like:

$2y$10$abcdefg...123456789...
 |  |    |        |
 |  |    |        +- the password hash
 |  |    +- the salt
 |  +- the cost parameter
 +- the algorithm type
In other words, the first part of the resulting hash is the same as the original input into the crypt function; it contains the algorithm type and parameters, the random salt and the hash result.

Input:  $password + $2y$10$abcdefg...
Output:             $2y$10$abcdefg...123456789...
                    ^^^^^^^^^^^^^^^^^
                   first part identical
When you confirm a password, you need the same, original salt again. Only with the same salt will the same password hash to the same hash. And it's still there in the hash, in a format that can be passed to crypt as is to repeat the same operation as when the hash was generated. That's why you need to feed both the password and hash into the validation function:

crypt($passwordToCheck, '$2y$10$abcdefg...123456789...')
crypt takes the first defined number of characters, up to and including abcdefg... and throws the rest away (that's why the salt needs to be a fixed number of characters). Therefore it equals the same operation as before:

crypt($passwordToCheck, '$2y$10$abcdefg...')
And will generate the same hash, if and only if $passwordToCheck is the same.

==================================================================================

@link https://goo.gl/HSx45s

Diagram based on Andrew Moore's structure

$2a$12$Some22CharacterSaltXXO6NC3ydPIrirIzk1NdnTz0L/aCaHnlBa
\___________________________/\_____________________________/
  \                            \
   \                            \ Actual Hash (31 chars)
    \
     \  $2a$   12$   Some22CharacterSaltXXO
        \__/    \    \____________________/
          \      \              \
           \      \              \ Salt (22 chars)
            \      \
             \      \ Number of Rounds (work factor)
              \
               \ Hash Header

$2a$ - Hash which is potentially generated with the buggy algorithm.
$2x$ - "compatibility" option the buggy Bcrypt implementation.
$2y$ - Hash generated with the new, corrected algorithm implementation (crypt_blowfish 1.1 and newer).
*/
class Bcrypt{

    private $rounds;

    public function __construct($rounds = 12){

        if(CRYPT_BLOWFISH != 1)
            throw new \Exception("Bcrypt is not supported on this server, please see the following to learn more: http://php.net/crypt");

        $this->rounds = $rounds;
    }

    public function makeSalt(){

        // openssl_random_pseudo_bytes(16) Fallback
        $seed = '';
        for($i = 0; $i < 16; $i++)
            $seed .= chr(mt_rand(0, 255));

        // get salt
        $salt = substr(strtr(base64_encode($seed), '+', '.'), 0, 22);

        return $salt;
    }

    public function makeHash($password){

        // Explain '$2y$' . $this->rounds . '$'
        // 2a selects bcrypt algorithm
        // $this->rounds is the workload factor

        $salt = new Str('$2y$');

        $salt = $salt->concat($this->rounds)->concat('$')->concat($this->makeSalt());

        $hash = crypt($password, (string)$salt);
        
        return $hash;
    }

    public function verify($password, $currHash){
        
        //Hash new password with old hash
        $hash = crypt($password, $currHash);

        return $hash === $currHash;
    }
}
