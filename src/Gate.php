<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Cache\Repository;

class Gate
{
    /**
     * @var Token
     */
    private ?Token $accessToken = null;

    /**
     * @param TokenProvider $tokenProvider
     * @param \Illuminate\Contracts\Cache\Repository  $repository
     * @param string $issuer
     * @param string $alg
     * @param int $ttl
     * @param string $storageKey
     */
    public function __construct(
        private TokenProvider $tokenProvider,
        private Repository $repository,
        private string $storageKey,
        private string $issuer,
        private string $alg,
        private int $ttl,
    ) {
    }

    /**
     * Validate token
     * 
     * @param string $jwt
     * @param bool $strict
     * 
     * @return ?Token
     * @throws \InvalidArgumentException
     */
    public function validate(string $jwt, bool $strict = false): ?Token
    {
        $this->accessToken = $this->tokenProvider->decode($jwt);

        if ($strict) {
            if (!$this->accessToken->stable($this->repository->get($this->tokenKey()))) {
                $this->accessToken = null;
            }
        }

        return $this->accessToken;
    }

    /**
     * Get token key
     */
    private function tokenKey(): string
    {
       return implode('-', [$this->storageKey, $this->accessToken?->jti]);
    }

    /**
     * Create token
     * 
     * @param array $payload
     * @param string|null $issuer
     * @param string|null $alg
     * @param int|null $ttl
     * @param bool $strict
     * 
     * @return Token
     */
    public function issueToken(
        array $payload, ?string $issuer = null, ?string $alg = null, ?int $ttl = null,
        bool $strict = false
    ): Token
    {
        $ttl = $ttl ?: $this->ttl;
        $issuer = $issuer ?: $this->issuer;
        $alg = $alg ?: $this->alg;
        
        $this->accessToken =  $this->tokenProvider->encode(
            $this->issuer, $payload, $this->alg, $this->ttl
        );

        if ($strict) {
            $this->repository->put(
                $this->tokenKey(), 
                $this->accessToken->getSignature(),
                $this->accessToken->ttl()
            );
        }

        return $this->accessToken;
    }

    /**
     * Clear token
     */
    public function clear()
    {
        $this->repository->delete($this->tokenKey());
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