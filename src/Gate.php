<?php

namespace AgenterLab\Gate;

class Gate
{
    /**
     * @var Token
     */
    private ?Token $accessToken = null;

    /**
     * @param TokenProvider $tokenProvider
     * @param string $issuer
     * @param string $alg
     * @param int $ttl
     */
    public function __construct(
        private TokenProvider $tokenProvider,
        private string $issuer,
        private string $alg,
        private int $ttl
    ) {
    }

    /**
     * Validate token
     * 
     * @param string $jwt
     * 
     * @return Token
     * @throws \InvalidArgumentException
     */
    public function validate(string $jwt): Token
    {
        $this->accessToken = $this->tokenProvider->decode($jwt);

        return $this->accessToken;
    }

    /**
     * Create token
     * 
     * @param array $payload
     * @param string|null $issuer
     * @param string|null $alg
     * @param int|null $ttl
     * 
     * @return Token
     */
    public function issueToken(array $payload, ?string $issuer = null, ?string $alg = null, ?int $ttl = null): Token
    {
        $ttl = $ttl ?: $this->ttl;
        $issuer = $issuer ?: $this->issuer;
        $alg = $alg ?: $this->alg;
        $this->accessToken =  $this->tokenProvider->encode($issuer, $payload, $alg, $ttl);

        return $this->accessToken;
    }

    /**
     * Get token
     * 
     * @return Token|null
     */
    public function getToken(): ?Token
    {
        return $this->accessToken;
    }
}