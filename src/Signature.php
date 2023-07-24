<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-07-24 10:13:45
 * 
 */

declare(strict_types=1);

namespace june\DataSecurity;

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
        if ($vSign !== $sign) {
            return false;
        }
        return true;
    }
}
