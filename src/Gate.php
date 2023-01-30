<?php

namespace AgenterLab\Gate;

class Gate
{
    /**
     * @var Token
     */
    private ?Token $token = null;

    /**
     * @param TokenProvider $tokenProvider
     * @param string $defaultAlgo
     * @param int $ttl
     */
    public function __construct(
        private TokenProvider $tokenProvider
    ) {
    }

    /**
     * Validate token
     * 
     * @param string $jwt
     * @param string $algo
     * @param null|string $issuer
     * 
     * @return Token
     * @throws \InvalidArgumentException
     */
    public function validate(string $jwt, string $algo, ?string $issuer = null): Token
    {
        list($iss, $jwt) = array_pad(explode(':', $jwt, 2), 2, null);

        if ($jwt) {
            $issuer = $iss;
        } else {
            $jwt = $iss;
        }

        if (!$issuer) {
            throw new \InvalidArgumentException('Token issuer missing');
        }

        $this->token =$this->tokenProvider->decode($issuer, $jwt, $algo);

        return $this->token;
    }

    /**
     * Create token
     * 
     * @param string $issuer
     * @param array $payload
     * @param string $algo
     * @param int $ttl
     * 
     * @return Token
     */
    public function issueToken(string $issuer, array $payload, string $algo): Token
    {
        return $this->tokenProvider->encode($issuer, $payload, $algo);
    }
}