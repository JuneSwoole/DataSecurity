# DataSecurity

#### Introduce
Encrypt and decrypt data using openssl

#### Install
```
composer require june/data_security
```
#### Example
1. symmetry encryption and decryption
```
use june\DataSecurity\Config;
use june\DataSecurity\Openssl;

$data = "Data that needs to be encrypted";

$config = new Config([
    "key"   => "your key",
    "iv"    => 'iv',
    "aad"   => 'aad'
]);
$openssl = new Openssl($config);
$ciphertext = $openssl->encrypted($data);
echo $ciphertext;

$data = $openssl->decryption($ciphertext);
echo $data;
```
2. asymmetry encryption and decryption
```
use june\DataSecurity\Config;
use june\DataSecurity\Openssl;

$data = "Data that needs to be encrypted";

$config = new Config([
    "privateKey" => "",
    "privateKeyFilePath" => "",
    "publicKey" => "",
    "publicKeyFilePath" => "",
]);
$openssl = new Openssl($config);

// Public key encryption
$ciphertext = $openssl->publicEncrypt($data);
echo $ciphertext;
$data = $openssl->privateDecrypt($ciphertext);
echo $data;

// Private key encryption
$ciphertext = $openssl->privateEncrypt($data);
echo $ciphertext;
$data = $openssl->publicDecrypt($ciphertext);
echo $data;
```
3. get signature and verification signature
```
use june\DataSecurity\Config;
use june\DataSecurity\Signature;

$data = [
    "name" => 'june'
];
$config = new Config([
    "appId"      => "your appId",
    "key"        => "your key"
]);
$signature = new Signature($config);
$sign = $signature->sign($data);
echo $sign;

$result = $signature->validate($sign, $data);
echo $result;

$config = new Config([
    "privateKey" => "",
    "privateKeyFilePath" => "",
    "publicKey" => "",
    "publicKeyFilePath" => "",
]);
$signature = new Signature($config);
$sign = $signature->opensslSign($data);
echo $sign;

$result = $signature->opensslVerify($sign, $data);
echo $result;
```

#### Singleton pattern
```
use june\DataSecurity\Config;
use june\DataSecurity\Signature;
use june\DataSecurity\Openssl;

$ciphertext = Openssl::getInstance($config)->encrypted($data);
Openssl::getInstance($config)->decryption($ciphertext);

$ciphertext = Openssl::getInstance($cofig)->publicEncrypt($data);
Openssl::getInstance($config)->privateDecrypt($ciphertext);

$ciphertext = Openssl::getInstance($cofig)->privateEncrypt($data);
Openssl::getInstance($config)->publicDecrypt($ciphertext);

$sign = Signature::getInstance($config)->sign($data);
Signature::getInstance($config)->validate($sign, $data)

$sign = Signature::getInstance($config)->opensslSign($data);
Signature::getInstance($config)->opensslVerify($sign, $data)
```