<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2025-03-23 11:15:41
 */

declare(strict_types=1);

namespace June\DataSecurity;

class Openssl
{
    use Singleton;

    protected Config $config;

    /** 常用加密算法映射（统一为小写） */
    private array $supportedCiphers = [
        'aes-128-cbc',
        'aes-256-cbc',
        'aes-128-gcm',
        'aes-256-gcm',
        'des-ede3-cbc',
        'bf-cbc'
    ];

    public function __construct(Config $config)
    {
        $this->config = $config;

        $cipher = strtolower($this->config->getCipher());
        if (!in_array($cipher, $this->supportedCiphers, true)) {
            throw new \InvalidArgumentException("Unsupported cipher: {$cipher}");
        }
    }

    private function getKeyResource(string $type): \OpenSSLAsymmetricKey
    {
        $keyStr = $type === 'public'
            ? ($this->config->getPublicKey() ?: file_get_contents($this->config->getPublicKeyFilePath()))
            : ($this->config->getPrivateKey() ?: file_get_contents($this->config->getPrivateKeyFilePath()));

        if (!str_contains($keyStr, 'BEGIN')) {
            $header = $type === 'public' ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN RSA PRIVATE KEY-----";
            $footer = $type === 'public' ? "-----END PUBLIC KEY-----" : "-----END RSA PRIVATE KEY-----";
            $keyStr = $header . "\n" . wordwrap($keyStr, 64, "\n", true) . "\n" . $footer;
        }

        $key = $type === 'public' ? openssl_pkey_get_public($keyStr) : openssl_pkey_get_private($keyStr);

        if (!$key) {
            $error = openssl_error_string();
            throw new \InvalidArgumentException(ucfirst($type) . " key unavailable: {$error}");
        }
        return $key;
    }

    private function generateIv(): string
    {
        $ivLength = openssl_cipher_iv_length(strtolower($this->config->getCipher()));
        $iv = openssl_random_pseudo_bytes($ivLength, $strong);
        if ($iv === false || !$strong) {
            throw new \RuntimeException("IV generation failed.");
        }
        return $iv;
    }

    public function encrypted(string $plaintext): string
    {
        $key = base64_decode($this->config->getKey(), true);
        if ($key === false) {
            throw new \InvalidArgumentException("Invalid base64-encoded key.");
        }

        $cipher = strtolower($this->config->getCipher());
        $iv = str_contains($cipher, 'gcm') ? $this->generateIv() : ($this->config->getIv() ?: $this->generateIv());

        $tag = '';
        $ciphertextRaw = str_contains($cipher, 'gcm')
            ? openssl_encrypt(
                $plaintext,
                $cipher,
                $key,
                $this->config->getOptions(),
                $iv,
                $tag,
                $this->config->getAad(),
                $this->config->getTagLength()
            )
            : openssl_encrypt(
                $plaintext,
                $cipher,
                $key,
                $this->config->getOptions(),
                $iv
            );

        if ($ciphertextRaw === false) {
            $error = openssl_error_string();
            throw new \RuntimeException("Encryption failed: {$error}");
        }

        return base64_encode(str_contains($cipher, 'gcm') ? $iv . $tag . $ciphertextRaw : $iv . $ciphertextRaw);
    }

    public function decryption(string $ciphertext): string|false
    {
        if (empty($ciphertext)) return false;

        $data = base64_decode($ciphertext, true);
        if ($data === false) return false;

        $cipher = strtolower($this->config->getCipher());
        $ivLength = openssl_cipher_iv_length($cipher);
        $key = base64_decode($this->config->getKey(), true);
        if ($key === false) return false;

        if (str_contains($cipher, 'gcm')) {
            $tagLength = $this->config->getTagLength();
            $iv = substr($data, 0, $ivLength);
            $tag = substr($data, $ivLength, $tagLength);
            $ciphertextRaw = substr($data, $ivLength + $tagLength);

            $decrypted = openssl_decrypt(
                $ciphertextRaw,
                $cipher,
                $key,
                $this->config->getOptions(),
                $iv,
                $tag,
                $this->config->getAad()
            );
        } else {
            $iv = substr($data, 0, $ivLength);
            $ciphertextRaw = substr($data, $ivLength);

            $decrypted = openssl_decrypt(
                $ciphertextRaw,
                $cipher,
                $key,
                $this->config->getOptions(),
                $iv
            );
        }

        return $decrypted !== false ? $decrypted : false;
    }

    public function publicEncrypt(string $plaintext): string
    {
        $publicKey = $this->getKeyResource('public');
        $encrypted = $this->opensslEncrypt($plaintext, $publicKey, 'public');
        return base64_encode($encrypted);
    }

    public function publicDecrypt(string $ciphertext): string
    {
        $ciphertext = base64_decode($ciphertext, true);
        if ($ciphertext === false) {
            throw new \InvalidArgumentException("Invalid base64 ciphertext.");
        }
        $publicKey = $this->getKeyResource('public');
        return $this->opensslDecrypt($ciphertext, $publicKey, 'public');
    }

    public function privateEncrypt(string $plaintext): string
    {
        $privateKey = $this->getKeyResource('private');
        $encrypted = $this->opensslEncrypt($plaintext, $privateKey, 'private');
        return base64_encode($encrypted);
    }

    public function privateDecrypt(string $ciphertext): string
    {
        $ciphertext = base64_decode($ciphertext, true);
        if ($ciphertext === false) {
            throw new \InvalidArgumentException("Invalid base64 ciphertext.");
        }
        $privateKey = $this->getKeyResource('private');
        return $this->opensslDecrypt($ciphertext, $privateKey, 'private');
    }

    private function opensslEncrypt(string $text, \OpenSSLAsymmetricKey $key, string $type): string
    {
        $details = openssl_pkey_get_details($key);
        $maxLength = ($details['bits'] / 8) - 11;
        $output = '';

        while ($text !== '') {
            $input = substr($text, 0, (int)$maxLength);
            $text = substr($text, (int)$maxLength);
            $crypttext = '';
            $success = $type === 'public'
                ? openssl_public_encrypt($input, $crypttext, $key)
                : openssl_private_encrypt($input, $crypttext, $key);

            if (!$success) {
                $error = openssl_error_string();
                throw new \RuntimeException("Asymmetric encryption failed: {$error}");
            }
            $output .= $crypttext;
        }

        return $output;
    }

    private function opensslDecrypt(string $text, \OpenSSLAsymmetricKey $key, string $type): string
    {
        $details = openssl_pkey_get_details($key);
        $maxLength = $details['bits'] / 8;
        $output = '';

        while ($text !== '') {
            $input = substr($text, 0, (int)$maxLength);
            $text = substr($text, (int)$maxLength);
            $crypttext = '';
            $success = $type === 'public'
                ? openssl_public_decrypt($input, $crypttext, $key)
                : openssl_private_decrypt($input, $crypttext, $key);

            if (!$success) {
                $error = openssl_error_string();
                throw new \RuntimeException("Asymmetric decryption failed: {$error}");
            }
            $output .= $crypttext;
        }

        return $output;
    }
}
