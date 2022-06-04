<?php

namespace AgenterLab\Gate;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthToken
{

    /**
     * Signature
     * 
     * @var string
     */
    private string $signature;

    /**
     * @param string $token
     * @param int $expires
     */
    public function __construct(
        private string $token,
        private int $expires,
        private ?object $payload = null
    )
    {
        $parts = explode('.', $this->token);
        $this->signature = end($parts);
    }

    public function getSignature()
    {
        return $this->signature;
    }

    public function getToken()
    {
        return $this->token;
    }

    public function getValiditiy()
    {
        return $this->expires;
    }

    /**
     * To array
     */
    public function toArray()
    {
        return [
            'ttl' => $this->expires - time(),
            'token' => $this->token,
            'expire_in' => $this->expires
        ];
    }

    /**
     * Create token
     * 
     * @param array $payload
     * @param string $key
     * @param string $algo
     * @param int $ttl
     * 
     * @return AuthToken
     */
    public static function create(
        array $payload,
        string $key,
        string $algo,
        int $ttl
    )
    {
        $expires = time() + $ttl;
        $payload['exp'] = $expires;

        $token = JWT::encode($payload, $key, $algo);

        return new static($token, $expires);
    }

    /**
     * validate token
     * 
     * @param string $jwt
     * @param string $key
     * @param string $algo
     * 
     * @return AuthToken
     */
    public static function validate(
        string $jwt,
        string $key,
        string $algo
    )
    {
        $payload = JWT::decode($jwt, new Key($key, $algo));
        return new static($jwt, $payload->exp, $payload);
    }

    /**
     * Dynamically retrieve attributes on the payload.
     *
     * @param  string  $key
     * @return mixed
     */
    public function __get($key)
    {
        return $this->payload?->$key;
    }
}