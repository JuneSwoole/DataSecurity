<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-07-24 14:44:09
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
     * 加密数据
     *
     * @param array|string $data
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    public function encrypted($plaintext): string
    {
        if (is_array($plaintext)) {
            $plaintext = json_encode($plaintext);
        }
        $key = base64_decode($this->config->getKey());
        $ivlen = openssl_cipher_iv_length($cipher = $this->config->getCipher());
        $iv = openssl_random_pseudo_bytes($ivlen);
        $Tag = $this->config->getTag();
        $ciphertext_raw = openssl_encrypt((string) $plaintext, $cipher, $key, $this->config->getOptions(), $iv, $Tag, $this->config->getTagLength());
        $hmac = hash_hmac($this->config->getHmac(), $ciphertext_raw, $key, true);
        return  base64_encode($iv . $hmac . $ciphertext_raw . $Tag);
    }

    /**
     * 解密数据
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
        $ivlen = openssl_cipher_iv_length($cipher = $this->config->getCipher());
        $tag_length = $this->config->getTagLength();
        $iv = substr($ciphertext, 0, $ivlen);
        $hmac = substr($ciphertext, $ivlen, $sha2len = 32);
        $ciphertext_raw = substr($ciphertext, $ivlen + $sha2len, -$tag_length);
        $tag = substr($ciphertext, -$tag_length);
        $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $this->config->getOptions(), $iv, $tag, $tag_length);
        $calcmac = hash_hmac($this->config->getHmac(), $ciphertext_raw, $key, true);
        if (hash_equals($hmac, $calcmac)) // timing attack safe comparison
        {
            return  $original_plaintext;
        }
        return false;
    }
}
