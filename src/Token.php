<?php

namespace AgenterLab\Gate;

use Firebase\JWT\JWT;
use stdClass;

class Token
{
    /**
     * @var stdClass
     */
    private stdClass $payloadObj;

    /**
     * @param string $header
     * @param string $payload
     * @param string $signature
     */
    protected function __construct(
        private string $header,
        private string $payload,
        private string $signature,
        private string $issuer = ''
    ) {
        $this->payloadObj = JWT::jsonDecode(JWT::urlsafeB64Decode($payload));

        if (!$issuer) {
            $this->issuer = $this->payloadObj->iss ?? '';
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
        return ($this->payloadObj->exp - $offset) <= time();
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
            'expire_in' => $this->payloadObj->exp
        ];
    }


    /**
     * Get payload obj
     * 
     * @return stdClass
     */
    public function getPayload()
    {
        return $this->payloadObj;
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
        $exp = $this->payloadObj->exp;

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
        return $this->payloadObj?->$key ?? null;
    }

    /**
     * From jwt
     * 
     * @param string $jwt
     * @param string $issuer
     * 
     * @return Token
     */
    public static function make(string $jwt, string $issuer = ''): Token
    {
        [$headb64, $bodyb64, $cryptob64] = explode('.', $jwt);

        return new static($headb64, $bodyb64, $cryptob64, $issuer);
    }
}
