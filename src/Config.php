<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-08-14 17:49:53
 * 
 */

declare(strict_types=1);

namespace june\DataSecurity;

class Config
{

    private $config = [
        "key"        => "",
        "cipher"     => "aes-128-gcm",
        "hmac"       => "sha256",
        "options"    => OPENSSL_RAW_DATA,
        "tag"        => "",
        "aad"        => "",
        "tag_length" => 16,
        "privateKey" => "",
        "privateKeyFilePath" => "",
        "publicKey" => "",
        "publicKeyFilePath" => "",
    ];

    public function __construct(array $config)
    {
        $this->config  = array_merge($this->config, $config);
    }

    public function getKey(): string
    {
        return $this->config['key'];
    }

    public function getCipher(): string
    {
        return $this->config['cipher'];
    }

    public function getHmac(): string
    {
        return $this->config['hmac'];
    }

    public function getOptions(): int
    {
        return $this->config['options'];
    }

    public function getTag(): ?string
    {
        return $this->config['tag'];
    }

    public function getAad(): string
    {
        return $this->config['aad'];
    }

    public function getTagLength(): int
    {
        return $this->config['tag_length'];
    }

    public function getPrivateKey(): string
    {
        return $this->config['privateKey'];
    }

    public function getPrivateKeyFilePath(): string
    {
        return $this->config['privateKeyFilePath'];
    }

    public function getPublicKey(): string
    {
        return $this->config['publicKey'];
    }

    public function getPublicKeyFilePath(): string
    {
        return $this->config['publicKeyFilePath'];
    }
}
