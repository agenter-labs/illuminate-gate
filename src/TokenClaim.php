<?php

namespace AgenterLab\Gate;

use Illuminate\Http\Request;

class TokenClaim
{
    /**
     * Create a new token repository instance.
     *
     * @param string $userAgent
     * @param int|string $userId
     * @param string $ip
     * @return void
     */
    public function __construct(
        protected int|string $user,
        protected string $ip,
        private string $userAgent,
        )
    {
    }


    /**
     * Get userId
     * 
     * @return int
     */
    public function user(): int|string
    {
        return $this->user;
    }


    /**
     * Get userAgent
     * 
     * @return string
     */
    public function userAgent(): string
    {
        return $this->userAgent;
    }


    /**
     * Get ip
     * 
     * @return string
     */
    public function ip(): string
    {
        return $this->ip;
    }

    /**
     * Get form request
     * 
     * @param int|string $user
     * @param \Illuminate\Http\Request $request
     * 
     * @return self
     */
    public static function fromRequest(int|string $user, Request $request): self
    {
        return new static(
            $user,
            $request->ip() ?: '',
            $request->userAgent() ?: ''
        );
    } 
}

// Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0