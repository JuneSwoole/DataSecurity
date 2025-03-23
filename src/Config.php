<?php

declare(strict_types=1);

namespace June\DataSecurity;

class Config
{
    private array $config;

    private const DEFAULTS = [
        'appId'               => '',
        'key'                 => '',
        'cipher'              => 'aes-128-gcm',
        'hmac'                => 'sha256',
        'options'             => OPENSSL_RAW_DATA,
        'iv'                  => '',
        'tag'                 => '',
        'aad'                 => '',
        'tag_length'          => 16,
        'privateKey'          => '',
        'privateKeyFilePath'  => '',
        'publicKey'           => '',
        'publicKeyFilePath'   => '',
        'padding'             => OPENSSL_ALGO_SHA256,
    ];

    public function __construct(array $config = [])
    {
        // 初始化为默认配置
        $this->config = self::DEFAULTS;
        // 合并传入配置
        foreach ($config as $key => $value) {
            $this->set($key, $value);
        }
    }

    /**
     * 通用 Getter
     */
    public function get(string $key): mixed
    {
        return $this->config[$key] ?? null;
    }

    /**
     * 通用 Setter
     */
    public function set(string $key, mixed $value): void
    {
        if (!array_key_exists($key, self::DEFAULTS)) {
            throw new \InvalidArgumentException("Invalid configuration key: '{$key}'");
        }
        $this->config[$key] = $value;
    }

    /**
     * 获取全部配置
     */
    public function all(): array
    {
        return $this->config;
    }

    /**
     * 校验必要配置项
     */
    public function validateRequired(array $requiredKeys = ['appId', 'key']): void
    {
        foreach ($requiredKeys as $key) {
            if (empty($this->config[$key])) {
                throw new \InvalidArgumentException("Configuration item '{$key}' is required.");
            }
        }
    }

    // 保持向后兼容的专用 Getter 方法
    public function getAppId(): string
    {
        return $this->get('appId');
    }
    public function getKey(): string
    {
        return $this->get('key');
    }
    public function getCipher(): string
    {
        return $this->get('cipher');
    }
    public function getHmac(): string
    {
        return $this->get('hmac');
    }
    public function getOptions(): int
    {
        return $this->get('options');
    }
    public function getIv(): ?string
    {
        return $this->get('iv');
    }
    public function getTag(): ?string
    {
        return $this->get('tag');
    }
    public function getAad(): string
    {
        return $this->get('aad');
    }
    public function getTagLength(): int
    {
        return $this->get('tag_length');
    }
    public function getPrivateKey(): string
    {
        return $this->get('privateKey');
    }
    public function getPrivateKeyFilePath(): string
    {
        return $this->get('privateKeyFilePath');
    }
    public function getPublicKey(): string
    {
        return $this->get('publicKey');
    }
    public function getPublicKeyFilePath(): string
    {
        return $this->get('publicKeyFilePath');
    }
    public function getPadding(): int
    {
        return $this->get('padding');
    }
}
