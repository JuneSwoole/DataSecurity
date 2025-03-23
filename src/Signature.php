<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-08-24 18:13:02
 * 
 */

declare(strict_types=1);

namespace June\DataSecurity;

class Signature
{
    use Singleton;

    protected Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * 获取签名
     *
     * @param array $data
     * @return string
     */
    public function sign(array $data = []): string
    {
        $signdata = $this->getSignString($data);
        return $this->generateHmacSignature($signdata);
    }

    /**
     * 验证签名
     *
     * @param string $sign
     * @param array $data
     * @return bool
     */
    public function validate(string $sign, array $data = []): bool
    {
        $vSign = $this->sign($data);
        return $vSign === $sign;
    }

    /**
     * 获取 OpenSSL 签名
     *
     * @param array $data
     * @return string
     * @throws \InvalidArgumentException
     */
    public function opensslSign(array $data): string
    {
        $privateKey = $this->getKeyResource('private');
        $signdata = $this->getSignString($data);
        $signature = '';
        if (!openssl_sign($signdata, $signature, $privateKey, $this->config->getPadding())) {
            throw new \RuntimeException('Failed to generate OpenSSL signature');
        }
        return base64_encode($signature);
    }

    /**
     * 验证 OpenSSL 签名
     *
     * @param string $sign
     * @param array $data
     * @return bool
     * @throws \InvalidArgumentException
     */
    public function opensslVerify(string $sign, array $data = []): bool
    {
        $publicKey = $this->getKeyResource('public');
        $signdata = $this->getSignString($data);
        $result = openssl_verify($signdata, base64_decode($sign), $publicKey, $this->config->getPadding());
        return $result === 1;
    }

    /**
     * 获取签名字符串
     *
     * @param array $data
     * @return string
     */
    private function getSignString(array $data): string
    {
        if ($this->config->getAppId()) {
            $data['appId'] = $this->config->getAppId();
        }
        ksort($data);
        $signdata = '';
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value);
            }
            $signdata .= $key . $value;
        }
        return $signdata;
    }

    /**
     * 生成 HMAC 签名
     *
     * @param string $data
     * @return string
     */
    private function generateHmacSignature(string $data): string
    {
        $key = base64_decode($this->config->getKey());
        $sign = hash_hmac($this->config->getHmac(), $data, $key, true);
        return base64_encode($sign);
    }


    /**
     * 获取 OpenSSL 密钥资源
     * @param string $type public|private
     * @return \OpenSSLAsymmetricKey
     */
    private function getKeyResource(string $type): \OpenSSLAsymmetricKey
    {
        $keyStr = $type === 'public' ? ($this->config->getPublicKey() ?: file_get_contents($this->config->getPublicKeyFilePath()))
            : ($this->config->getPrivateKey() ?: file_get_contents($this->config->getPrivateKeyFilePath()));

        if ($this->config->getPrivateKey()) {
            $header = $type === 'public' ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN RSA PRIVATE KEY-----";
            $footer = $type === 'public' ? "-----END PUBLIC KEY-----" : "-----END RSA PRIVATE KEY-----";
            $keyStr = $header . "\n" . wordwrap($keyStr, 64, "\n", true) . "\n" . $footer;
        }
        $key = $type === 'public' ? openssl_pkey_get_public($keyStr) : openssl_pkey_get_private($keyStr);

        if (!$key) {
            throw new \InvalidArgumentException(ucfirst($type) . " key unavailable, check configuration.");
        }
        return $key;
    }
}
