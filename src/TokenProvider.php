<?php

namespace AgenterLab\Gate;

use AgenterLab\Gate\Contracts\KeyStoreInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use DomainException;

class TokenProvider
{
    /**
     * @param KeyStoreInterface $keyStore
     */
    public function __construct(private KeyStoreInterface $keyStore) {
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
        return $this->keyStore->getKey($issuer . '.key');
    }
    /**
     * Get Public key
     * 
     * @param string $issuer
     * @param null|string $alg
     * 
     * @return Key
     */
    private function publicKey(string $issuer, string $alg): Key
    {

        if (empty(JWT::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        $keyType = 'openssl' == JWT::$supported_algs[$alg][0] ? 'pub' : 'key';
        
        return new Key($this->keyStore->getKey($issuer . '.' . $keyType), $alg);
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
    public function encode(string $issuer, array $payload, string $alg, int $ttl): Token
    {
        $time = time();

        if (empty($payload['jti'])) {
            $payload['jti'] = self::getId();
        }

        $payload['iss'] = $issuer;
        $payload['iat'] = $time;
        $payload['nbf'] = $time;
        $payload['exp'] = $time + $ttl;

        $jwt = JWT::encode($payload, $this->privateKey($issuer), $alg, $issuer);

        return Token::make($jwt, $issuer);
    }

    /**
     * Decode token
     * 
     * @param string $jwt
     * 
     * @return Token
     */
    public function decode(string $jwt): Token
    {
        $token = Token::make($jwt);

        JWT::decode($jwt, $this->publicKey($token->getIssuer(), $token->getAlgorithm()));

        return $token;
    }

    /**
     * Get token ID
     * 
     * @return string
     */
    public static function getId(): string
    {
        return uniqid() . bin2hex(random_bytes(8));
    }
}
