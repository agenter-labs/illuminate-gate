<?php

namespace AgenterLab\Gate;

use Firebase\JWT\JWT;
use stdClass;

class Token
{
    /**
     * @var stdClass
     */
    private stdClass $payload;

    /**
     * @var string
     */
    private string $issuer;

    /**
     * @var string
     */
    private string $algorithm;

    /**
     * @param string $header64
     * @param string $payload64
     * @param string $signature
     */
    protected function __construct(
        private string $header64,
        private string $payload64,
        private string $signature
    ) {

        $header = JWT::jsonDecode(JWT::urlsafeB64Decode($header64));
        $this->payload = JWT::jsonDecode(JWT::urlsafeB64Decode($payload64));

        $this->issuer = $this->payload->iss ?? '';
        $this->algorithm = $header->alg ?? '';
    }

    /**
     * Get Issuer
     * 
     * @return string
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * Get Issuer
     * 
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * Get signature
     * 
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * Check expired
     * 
     * @param int $offset
     * 
     * @return bool
     */
    public function expired(int $offset = 0): bool
    {
        return ($this->payload->exp - $offset) <= time();
    }

    /**
     * To string
     * 
     * @return string
     */
    public function toString()
    {
        return implode('.', [$this->header64, $this->payload64, $this->signature]);
    }

    /**
     * To array
     * 
     * @return array
     */
    public function toArray()
    {
        return [
            'ttl' => $this->ttl(),
            'token' => $this->toString(),
            'expire_in' => $this->payload->exp
        ];
    }


    /**
     * Get payload obj
     * 
     * @return stdClass
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Match signature
     * 
     * @param string $signature
     * 
     * @return bool
     */
    public function stable(string $signature): bool
    {
        return $this->signature == $signature;
    }

    /**
     * Get TTl
     * 
     * @return int
     */
    public function ttl(): int
    {
        $exp = $this->payload->exp;

        return $exp - time();
    }

    /**
     * Dynamically retrieve attributes on the payload.
     *
     * @param  string  $key
     * @return mixed
     */
    public function __get($key)
    {
        return $this->payload?->$key ?? null;
    }

    /**
     * From jwt
     * 
     * @param string $jwt
     * @param string $issuer
     * 
     * @return Token
     */
    public static function make(string $jwt): Token
    {
        [$headb64, $bodyb64, $signature] = explode('.', $jwt);

        return new static($headb64, $bodyb64, $signature);
    }
}
