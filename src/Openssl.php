<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2024-06-12 16:57:29
 * 
 */

declare(strict_types=1);

namespace June\DataSecurity;

class Openssl
{
    use Singleton;

    /**
     * 配置
     *
     * @var Config
     */
    protected $config;

    public function __construct(Config $config)
    {
        $this->config   = $config;
    }

    /**
     * 对称加密数据
     *
     * @param string $plaintext
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    public function encrypted(string $plaintext): string
    {
        $key = base64_decode($this->config->getKey());
        $cipher = $this->config->getCipher();
        $iv = $this->config->getIv();
        if (empty($iv)) {
            $ivlen = openssl_cipher_iv_length($cipher);
            $iv = openssl_random_pseudo_bytes($ivlen);
        }
        $Tag = $this->config->getTag();
        $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $this->config->getOptions(), $iv, $Tag, $this->config->getAad(), $this->config->getTagLength());
        return  base64_encode($ciphertext_raw . $Tag);
    }

    /**
     * 对称解密数据
     *
     * @param string $ciphertext 密文
     * @return string|false
     * @author juneChen <juneswoole@163.com>
     */
    public function decryption(string $ciphertext)
    {
        if (empty($ciphertext)) {
            return false;
        }
        $ciphertext = base64_decode($ciphertext);
        $key = base64_decode($this->config->getKey());
        $cipher = $this->config->getCipher();
        $iv = $this->config->getIv();
        if (empty($iv)) {
            $ivlen = openssl_cipher_iv_length($cipher);
            $iv = openssl_random_pseudo_bytes($ivlen);
        }
        $tag_length = $this->config->getTagLength();
        $ciphertext_raw = substr($ciphertext, 0, -$tag_length);
        $tag = substr($ciphertext, -$tag_length);
        $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $this->config->getOptions(), $iv, $tag, $this->config->getAad());
        return  $original_plaintext;
    }

    /**
     * 非对称公钥加密数据
     *
     * @param string $plaintext
     * @return string
     * @author juneChen <juneswoole@163.com>
     * @throws UnexpectedValueException
     */
    public function publicEncrypt(string $plaintext): string
    {
        if ($this->config->getPublicKey()) {
            $publicKey = "-----BEGIN PUBLIC KEY-----\n" .
                wordwrap($this->config->getPublicKey(), 64, "\n", true) .
                "\n-----END PUBLIC KEY-----";
        } else {
            $publicKey = file_get_contents($this->config->getPublicKeyFilePath());
        }
        $pub_key = openssl_pkey_get_public($publicKey);
        if (!$pub_key) {
            throw new \InvalidArgumentException('Public key unavailable,Check whether the public key is correctly configured');
        }
        $output = $this->opensslEncrypt($plaintext, $pub_key, 'public');
        return base64_encode($output);
    }

    /**
     * 非对称公钥解密数据
     *
     * @param string $ciphertext 密文
     * @return string|null
     * @throws UnexpectedValueException
     * @author juneChen <juneswoole@163.com>
     */
    public function publicDecrypt(string $ciphertext): ?string
    {
        if (empty($ciphertext)) {
            return false;
        }
        $ciphertext = base64_decode($ciphertext);
        if ($this->config->getPublicKey()) {
            $publicKey = "-----BEGIN PUBLIC KEY-----\n" .
                wordwrap($this->config->getPublicKey(), 64, "\n", true) .
                "\n-----END PUBLIC KEY-----";
        } else {
            $publicKey = file_get_contents($this->config->getPublicKeyFilePath());
        }
        $pub_key = openssl_pkey_get_public($publicKey);
        if (!$pub_key) {
            throw new \InvalidArgumentException('Public key unavailable,Check whether the public key is correctly configured');
        }
        return $this->opensslDecrypt($ciphertext, $pub_key, 'public');
    }

    /**
     * 非对称私钥加密数据
     *
     * @param string $plaintext
     * @return string
     * @author juneChen <juneswoole@163.com>
     * @throws UnexpectedValueException
     */
    public function privateEncrypt(string $plaintext): string
    {
        if ($this->config->getPrivateKey()) {
            $privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" .
                wordwrap($this->config->getPrivateKey(), 64, "\n", true) .
                "\n-----END RSA PRIVATE KEY-----";
        } else {
            $privateKey = file_get_contents($this->config->getPrivateKeyFilePath());
        }
        $pri_key = openssl_pkey_get_private($privateKey);
        if (!$pri_key) {
            throw new \InvalidArgumentException('Private key unavailable,Check whether the private key is correctly configured');
        }
        $output = $this->opensslEncrypt($plaintext, $pri_key, 'private');
        return base64_encode($output);
    }

    /**
     * 非对称私钥解密数据
     *
     * @param string $ciphertext 密文
     * @return string|null
     * @author juneChen <juneswoole@163.com>
     * @throws UnexpectedValueException
     */
    public function privateDecrypt(string $ciphertext): ?string
    {
        if (empty($ciphertext)) {
            return null;
        }
        $ciphertext = base64_decode($ciphertext);
        if ($this->config->getPrivateKey()) {
            $privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" .
                wordwrap($this->config->getPrivateKey(), 64, "\n", true) .
                "\n-----END RSA PRIVATE KEY-----";
        } else {
            $privateKey = file_get_contents($this->config->getPrivateKeyFilePath());
        }

        $pri_key = openssl_pkey_get_private($privateKey);

        if (!$pri_key) {
            throw new \InvalidArgumentException('Private key unavailable,Check whether the private key is correctly configured');
        }
        return $this->opensslDecrypt($ciphertext, $pri_key, 'private');
    }

    /**
     * 非对称加密数据
     *
     * @param string $text 明文字符串
     * @param \OpenSSLAsymmetricKey $key 密钥
     * @param string $type public|private
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    private function opensslEncrypt(string $text, \OpenSSLAsymmetricKey $key, string $type = 'public'): string
    {
        $etails = openssl_pkey_get_details($key);
        $maxLength = $etails['bits'] / 8 - 11;
        $output = '';
        while ($text) {
            $input = substr($text, 0, $maxLength);
            $text = substr($text, $maxLength);
            if ($type == 'public') {
                openssl_public_encrypt($input, $crypttext, $key);
            } else {
                openssl_private_encrypt($input, $crypttext, $key);
            }
            $output .= $crypttext;
        }
        return $output;
    }

    /**
     * 非对称解密数据
     *
     * @param string $text 明文字符串
     * @param \OpenSSLAsymmetricKey $key 密钥
     * @param string $type public|private
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    private function opensslDecrypt(string $text, \OpenSSLAsymmetricKey $key, string $type = 'public'): string
    {
        $etails = openssl_pkey_get_details($key);
        $maxLength = $etails['bits'] / 8;
        $output = '';
        while ($text) {
            $input = substr($text, 0, $maxLength);
            $text = substr($text, $maxLength);
            if ($type == 'public') {
                openssl_public_decrypt($input, $crypttext, $key);
            } else {
                openssl_private_decrypt($input, $crypttext, $key);
            }
            $output .= $crypttext;
        }
        return $output;
    }
}
