<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Cache\Repository;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class TokenGuard extends \Illuminate\Auth\TokenGuard
{
    /**
     * The name of the guard. Typically "web".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected $name = 'api';

    /**
     * Auth related account
     */
    private $accountId = null;

    /**
     * @var int
     */
    private $companyId = null;
    
    /**
     * @var int
     */
    private $tokenExp = null;
    
    /**
     * @var string
     */
    private $jwtToken;

    const SLEEP_TIME = 300;

    const ALGO = 'HS256';

    /**
     * Create a new authentication guard.
     *
     * @param  \Illuminate\Contracts\Cache\Repository  $repository
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $inputKey
     * @param  string  $storageKey
     * @return void
     */
    public function __construct(
        private Repository $repository,
        private int $ttl,
        private string $key,
        private bool $strict,
        UserProvider $provider,
        Request $request,
        string $inputKey = 'api_token',
        string $storageKey = 'api_token'
        )
    {
        parent::__construct($provider, $request, $inputKey, $storageKey);
    }

    /**
     * Get the currently authenticated user.
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $token = $this->getTokenForRequest();
    
        if (! empty($token)) {
            $decoded = JWT::decode($token, new Key($this->key, self::ALGO));
            $this->user = $this->provider->retrieveById($decoded?->aud);
            $this->accountId = $decoded?->sub;
            $this->companyId = $decoded?->org;
            $this->tokenExp = $decoded?->exp;

            if ($this->strict) {
                $exists = $this->repository->get($this->tokenKey());
                if (!$exists) {
                    $this->user = null;
                }
            }
        }

        if ($this->user) {
            $this->jwtToken = $token;
        }
        
        return $this->user;
    }

    public function tokenToArray() {

        $token = $this->getToken();

        if (!$token) {
            throw new \InvalidArgumentException("Authenticate request before fetch token");
        }

        return [
            'ttl' => $this->ttl,
            'token' => $token,
            'expire_in' => $this->expireIn()
        ];
    }
    
    public function getToken() {

        if (!$this->id()) {
            return;
        }

        if ($this->jwtToken) {
            return $this->jwtToken;
        }

        $this->jwtToken = $this->repository->remember(
            $this->tokenKey(), 
            $this->ttl, 
            function () {

                $this->tokenExp = time() + $this->ttl;
                $payload = $this->getPayload();
                $payload['exp'] = $this->tokenExp;
    
                return JWT::encode(
                    $payload, 
                    $this->key, 
                    self::ALGO
                );
            });
            
        return $this->jwtToken;
    }

    /**
     * Get account
     */
    public function account() {
        return $this->accountId;
    }

    /**
     * Get company Id
     * 
     * @return int
     */
    public function company() {
        return $this->companyId;
    }

    public function expireIn() {
        return $this->tokenExp;
    }

    /**
     * @inheritdoc
     */
    public function getTokenForRequest()
    {
        $token = $this->request->headers->get($this->inputKey);

        if (empty($token)) {
            $token = $this->request->cookie($this->inputKey);
        }

        return $token;
    }


    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        $this->clearUserDataFromStorage();

        $this->user = null;
    }

    /**
     * Get refresh token
     */
    public function refreshToken() {
        
        $this->clearUserDataFromStorage();

        return $this;
    }

    /**
     * Remove the user data from the session and cookies.
     *
     * @return void
     */
    protected function clearUserDataFromStorage()
    {
        $id = $this->id();

        if ($id) {
            $this->repository->delete($this->tokenKey());
        }
    }



    /**
     * Get token key
     */
    private function tokenKey(): string
    {
       return implode('-', [
            $this->storageKey,
            $this->id()
        ]);
    }

    /**
     * Get token payload
     */
    private function getPayload(): array
    {
        $payload = [
            'aud' => $this->id()
        ];

        if ($this->accountId) {
            $payload['sub'] = $this->accountId;
        }
        
        if ($this->companyId) {
            $payload['org'] = $this->companyId;
        }

        return $payload;
    }
}