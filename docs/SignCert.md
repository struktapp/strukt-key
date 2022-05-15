```php
// Let's assume that this script is set to receive a CSR that has
// been pasted into a textarea from another page
// $csrdata = $_POST["CSR"];

// We will sign the request using our own "certificate authority"
// certificate.  You can use any certificate to sign another, but
// the process is worthless unless the signing certificate is trusted
// by the software/users that will deal with the newly signed certificate

$dn = array(
    "countryName" => "GB",
    "stateOrProvinceName" => "Somerset",
    "localityName" => "Glastonbury",
    "organizationName" => "The Brain Room Limited",
    "organizationalUnitName" => "PHP Documentation Team",
    "commonName" => "Wez Furlong",
    "emailAddress" => "wez@example.com"
);

/**
* We need our CA cert and its private key and
*  generate a new private (and public) key pair
*/
$privkey = openssl_pkey_new(array(

    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
));

// Generate a certificate signing request
$csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha384'));

// Generate a self-signed cert, valid for 365 days
$cacert = openssl_csr_sign($csr, null, $privkey, $days=365, array('digest_alg' => 'sha384'));

$usercert = openssl_csr_sign($csr, $cacert, $privkey, $days, array('digest_alg'=>'sha384') );

// Now display the generated certificate so that the user can
// copy and paste it into their local configuration (such as a file
// to hold the certificate for their SSL server)
openssl_x509_export($usercert, $certout);
echo $certout;

// Show any errors that occurred here
while (($e = openssl_error_string()) !== false) {
    echo $e . "\n";
}
```