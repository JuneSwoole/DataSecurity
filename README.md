# DataSecurity

#### Introduce
Encrypt and decrypt data using openssl

#### Install
```
composer require june/data_security
```
#### Example
1. Encryption
```
use june\DataSecurity\Config;
use june\DataSecurity\Openssl;

$data = "Data that needs to be encrypted";
$config = [
    "key"        => "your key"
];
$config = new Config($config);
$openssl = new Openssl($config);
$ciphertext = $openssl->encrypted($data);
echo $ciphertext;
```
2. Decryption
```
use june\DataSecurity\Config;
use june\DataSecurity\Openssl;

$ciphertext = "aveG3WlSQ1MTFV3GGyJfOjr4gPY+SopPoZVOB1qjivRvvnAdTo7qCPRb+D5EwhQtftWENPNquxOENRPdiXdwRmNu2w9cvTLzdMMsIIprwu12IQA8Ao+2nlYCtg==";
$config = [
    "key"        => "your key"
];
$config = new Config($config);
$openssl = new Openssl($config);
$data = $openssl->decryption($ciphertext);
echo $data;
```
3. Get signature
```
use june\DataSecurity\Config;
use june\DataSecurity\Signature;

$data = [
    "name" => 'june'
];
$config = [
    "appId"      => "your appId",
    "key"        => "your key"
];
$config = new Config($config);
$signature = new Signature($config);
$sign = $signature->sign($data);
echo $sign;
```
4. Verification signature
```
use june\DataSecurity\Config;
use june\DataSecurity\Signature;

$data = [
    "name" => 'june'
];
$sign = 'ul3BFmxyaGMEWMLqWvwQCJJbtQAz/c8JScMS7iyikAo=';
$config = [
    "appId"      => "your appId",
    "key"        => "your key"
];
$config = new Config($config);
$signature = new Signature($config);
$result = $signature->validate($sign, $data);
echo $result;
```
#### Singleton pattern
```
$ciphertext = \june\DataSecurity\Openssl::getInstance($config)->encrypted($data);

\june\DataSecurity\Openssl::getInstance($config)->decryption($ciphertext);

$sign = \june\DataSecurity\Signature::getInstance($config)->sign($data);

\june\DataSecurity\Signature::getInstance($config)->validate($sign, $data)
```