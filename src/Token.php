<?php

namespace AgenterLab\Gate;

use Firebase\JWT\JWT;
use stdClass;

class Token
{
    /**
     * @var stdClass
     */
    private ?stdClass $payloadObj = null;

    /**
     * @var Auth
     */
    private ?Auth $auth = null;

    /**
     * @param string $header
     * @param string $payload
     * @param string $signature
     */
    public function __construct(
        private string $header,
        private string $payload,
        private string $signature,
        private string $issuer = ''
    ) {

        if (!$issuer) {
            $this->issuer = $this->parseIssuer();
        }
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
        return ($this->auth()->exp - $offset) <= time();
    }

    /**
     * To string
     * 
     * @return string
     */
    public function toString()
    {
        return $this->issuer . ':' . implode('.', [$this->header, $this->payload, $this->signature]);
    }

    /**
     * To array
     * 
     * @return array
     */
    public function toArray()
    {
        return [
            'ttl' => $this->parseTTL(),
            'token' => $this->toString(),
            'expire_in' => $this->auth()->exp
        ];
    }


    /**
     * Get payload obj
     * 
     * @return stdClass
     */
    public function getPayload(): stdClass
    {
        if (is_null($this->payloadObj)) {
            $this->payloadObj = JWT::jsonDecode(JWT::urlsafeB64Decode($this->payload));
        }
        
        return $this->payloadObj;
    }

    /**
     * Get Auth
     * 
     * @return Auth
     */
    public function auth(): Auth
    {
        if (is_null($this->auth)) {
            $this->auth = new Auth($this->issuer, $this->getPayload());
        }
        
        return $this->auth;
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
    private function parseTTL(): int
    {
        $exp = $this->auth()->exp;

        return $exp - time();
    }

    /**
     * Get Issuer
     * 
     * @return string
     */
    private function parseIssuer(): string
    {
        return $this->auth()->iss;
    }

    /**
     * From jwt
     * 
     * @param string $jwt
     * 
     * @return Token
     */
    public static function make(string $jwt): Token
    {
        [$headb64, $bodyb64, $cryptob64] = explode('.', $jwt);

        return new static($headb64, $bodyb64, $cryptob64);
    }
}
