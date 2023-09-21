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
     * 获取签名
     *
     * @param array $data
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    public function sign(array $data = []): string
    {
        $signdata = $this->getSignString($data);
        $key = base64_decode($this->config->getKey());
        $sign = hash_hmac($this->config->getHmac(), $signdata, $key, true);
        return base64_encode($sign);
    }

    /**
     * 验证签名
     *
     * @param string $sign
     * @param array $data
     * @return boolean
     * @author juneChen <juneswoole@163.com>
     */
    public function validate(string $sign, array $data = []): bool
    {
        $vSign = $this->sign($data);
        return $vSign === $sign;
    }

    /**
     * 获取 openssl 签名
     *
     * @param array $data
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    function opensslSign(array $data): string
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
        $signdata = $this->getSignString($data);
        openssl_sign($signdata, $sign, $pri_key, $this->config->getPadding());
        $sign = base64_encode($sign);
        return $sign;
    }

    /**
     * openssl 签名验证
     *
     * @param string $sign 签名串
     * @param array $data  验证数据
     * @return boolean
     * @author juneChen <juneswoole@163.com>
     */
    function opensslVerify(string $sign, array $data = []): bool
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
        $signdata = $this->getSignString($data);
        $result = (bool)openssl_verify($signdata, base64_decode($sign), $pub_key, $this->config->getPadding());
        return $result;
    }

    /**
     * 获取签名字符串
     *
     * @param array $data
     * @return string
     * @author juneChen <juneswoole@163.com>
     */
    private function getSignString(array $data): string
    {
        if ($this->config->getAppId()) {
            $data['appId'] = $this->config->getAppId();
        }
        ksort($data);
        $signdata = "";
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value);
            }
            $signdata .= $key . $value;
        }
        return $signdata;
    }
}
