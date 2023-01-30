<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Auth\TokenGuard;

class JwtGuard extends TokenGuard
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
     * @var int
     */
    private $tokenId = null;
    
    /**
     * @var Token
     */
    private ?Token $accessToken = null;
    
    /**
     * @var int
     */
    private ?int $organizationId = null;
    
    /**
     * @var int
     */
    private ?int $accountId = null;

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
        private Cache $cache,
        private Gate $gate,
        private string $claim,
        private string $issuer,
        private bool $strict,
        UserProvider $provider,
        Request $request,
        string $inputKey = 'access-token',
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

        $jwt = $this->getTokenForRequest();
    
        if (!empty($jwt)) {

            $accessToken = $this->gate->validate($jwt, self::ALGO);
            $this->user = $this->provider->retrieveById($accessToken->auth()->{$this->claim});
            $this->tokenId = $accessToken->auth()->jti;
            $this->organizationId = $accessToken->auth()->org;
            $this->accountId =$this->claim == 'aud' ? $accessToken->auth()->user() : $accessToken->auth()->serviceUser();
            
            if ($this->strict) {
                $signature = $this->cache->get($this->tokenKey());
                if (!$accessToken->stable($signature)) {
                    $this->user = null;
                }
            }

            if ($this->user) {
                $this->accessToken = $accessToken;
            }
        }
        
        return $this->user;
    }


    public function toArray() {

        $token = $this->getAccessToken();

        if (!$token) {
            throw new \InvalidArgumentException("Authenticate request before fetch token");
        }

        return $token->toArray();
    }
    
    public function getAccessToken() {

        if (!$this->id()) {
            return;
        }

        $this->refreshExpiring();

        if ($this->accessToken) {
            return $this->accessToken;
        }


        $this->accessToken = $this->gate->issueToken(
            $this->issuer, $this->getPayload(), self::ALGO
        );

        if ($this->strict) {
            $this->cache->put(
                $this->tokenKey(), $this->accessToken->getSignature()
            );
        }

        return $this->accessToken;
    }

    private function refreshExpiring() {

        if (!$this->accessToken) {
            return;
        }

        if (($this->accessToken->expired(self::SLEEP_TIME))) {
            $this->refreshToken();
        }
    }

    /**
     * @inheritdoc
     */
    public function getTokenForRequest(string $key = null)
    {
        $key = $key ?: $this->inputKey;

        $token = $this->request->headers->get($key);

        if (empty($token)) {
            $token = $this->request->cookie($key);
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
            $this->cache->delete($this->tokenKey());
        }

        $this->accessToken = null;
    }

    /**
     * Get token key
     */
    private function tokenKey(): string
    {
       return implode('-', [$this->storageKey, $this->tokenId]);
    }

    /**
     * Get token payload
     */
    private function getPayload(): array
    {
        $payload = [
            'jti' => $this->tokenId,
            $this->claim => $this->id()
        ];

        if ($this->accountId) {
            $claim = $this->claim == 'aud' ? 'sub' : 'aud';
            $payload[$claim] = $this->accountId;
        }
        
        if ($this->organizationId) {
            $payload['org'] = $this->organizationId;
        }

        return $payload;
    }

    /**
     * Set company Id
     * 
     */
    public function setCompany(int $id) {

        if ($this->organizationId != $id) {
            $this->accessToken = null;
        }

        $this->organizationId = $id;

        return $this;
    }

    /**
     * Set company Id
     * 
     */
    public function setAccount(int $id) {

        if ($this->accountId != $id) {
            $this->accessToken = null;
        }

        $this->accountId = $id;

        return $this;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return $this
     */
    public function setUser(Authenticatable $user)
    {
        $id = $this->id();

        $this->user = $user;

        if ($id != $this->id()) {
            $this->accessToken = null;
        }

        return $this;
    }
}