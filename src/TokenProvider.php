<?php

namespace AgenterLab\Gate;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class TokenProvider
{
    /**
     * @var string[]
     */
    private array $privateKeys = [];

    /**
     * @var Key[]
     */
    private array $publicKeys = [];

    /**
     * @param string $keyPath
     * @param string $defaultAlgo
     * @param int $ttl
     */
    public function __construct(
        private string $keyPath,
        private string $defaultAlgo = 'HS256',
        private int $ttl = 600
    ) {
    }

    /**
     * Get private key
     * 
     * @param string $issuer
     * 
     * @return string
     */
    private function privateKey(string $issuer): string
    {
        if (empty($this->privateKeys[$issuer])) {

            $pkPath = $this->keyPath . '/' . $issuer . '.key';

            if (!is_file($pkPath)) {
                throw new \InvalidArgumentException('Invalid key path: ' . $pkPath);
            }

            $this->privateKeys[$issuer] = file_get_contents($pkPath);
        }

        return $this->privateKeys[$issuer];
    }
    /**
     * Get Public key
     * 
     * @param string $issuer
     * @param null|string $algo
     * 
     * @return Key
     */
    private function publicKey(string $issuer, ?string $algo = null): Key
    {

        if (empty($this->publicKeys[$issuer])) {

            $algo = $algo ?: $this->defaultAlgo;

            $pkPath = $this->keyPath . '/' . $issuer . '.pub';

            if (!is_file($pkPath)) {
                throw new \InvalidArgumentException('Invalid key path: ' . $pkPath);
            }

            $this->publicKeys[$issuer] = new Key(file_get_contents($pkPath), $algo);
        }

        return $this->publicKeys[$issuer];
    }

    /**
     * Get access token
     * 
     * @param string $issuer
     * @param array $payload
     * @param null|string $algo
     * @param null|ttl $ttl
     * 
     * @return Token
     */
    public function encode(string $issuer, array $payload, ?string $algo = null, ?int $ttl = null): Token
    {
        $time = time();
        $ttl = $ttl ?: $this->ttl;
        $algo = $algo ?: $this->defaultAlgo;

        $payload['iss'] = $issuer;
        $payload['iat'] = $time;
        $payload['nbf'] = $time;
        $payload['exp'] = $time + $ttl;

        $jwt = JWT::encode($payload, $this->privateKey($issuer), $algo, $issuer);

        [$headb64, $bodyb64, $cryptob64] = explode('.', $jwt);
        return new Token($headb64, $bodyb64, $cryptob64, $issuer);
    }

    /**
     * Decode access token
     * 
     * @param string $issuer
     * @param string $jwt
     * @param null|string $algo
     * 
     * @return Token
     */
    public function decode(string $issuer, string $jwt, ?string $algo = null): Token
    {
        JWT::decode($jwt, $this->publicKey($issuer, $algo));

        return Token::make($jwt);
    }
}
