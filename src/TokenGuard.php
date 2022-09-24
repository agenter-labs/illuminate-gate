<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Auth\Authenticatable;

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
    private $tokenId = null;
    
    /**
     * @var AuthToken
     */
    private $accessToken;

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
        private int $ttl,
        private string $key,
        private bool $strict,
        private string $idStorageKey,
        private string $idProviderKey,
        private string $userClaim,
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

            $accessToken = AuthToken::validate($token, $this->key, self::ALGO);

            $this->user = $this->provider->retrieveById($accessToken->{$this->userClaim});
            $this->accountId = $accessToken->sub;
            $this->companyId = $accessToken->org;
            $this->tokenId = $accessToken->jti;
            
            if ($this->strict) {
                $signature = $this->cache->get($this->tokenKey());
                if ($signature != $accessToken->getSignature()) {
                    $this->user = null;
                }
            }

            if ($this->user) {
                $this->accessToken = $accessToken;
            }
        }
        
        return $this->user;
    }

    /**
     * ID login
     * Login using token from id provider
     */
    public function idTokenLogin()
    {
        if (!$this->accountId) {
            $this->verifyIdToken();
        }

        if ($this->accountId && !$this->user) {
            $this->user = $this->provider->retrieveByCredentials(['account_id' => $this->accountId]);
        }

        $this->accessToken = null;
        
        return $this;
    }

    /**
     * Verify service token
     */
    private function verifyIdToken()
    {
        $token = $this->getTokenForRequest($this->idStorageKey, true);
    
        if (empty($token)) {
            throw new \InvalidArgumentException("Must provide id token");
        }

        if (empty($this->idProviderKey)) {
            throw new \InvalidArgumentException("Must provide id key");
        }

        $decoded = AuthToken::validate($token, $this->idProviderKey, self::ALGO);

        $this->accountId = $decoded?->sub;
        $this->tokenId = $decoded?->jti;
    }


    public function tokenToArray() {

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



        $this->accessToken = AuthToken::create(
            $this->getPayload(), 
            $this->key, 
            self::ALGO,
            $this->ttl
        );

        if ($this->strict) {
            $this->cache->put(
                $this->tokenKey(), 
                $this->accessToken->getSignature(), 
                $this->ttl
            );
        }

        return $this->accessToken;
    }

    private function refreshExpiring() {

        if (!$this->accessToken) {
            return;
        }

        if (($this->accessToken->getValiditiy() - self::SLEEP_TIME) <= time()) {
            $this->refreshToken();
        }
    }

    /**
     * Get account
     */
    public function getAccountId() {
        return $this->accountId;
    }

    /**
     * Get company Id
     * 
     * @return int
     */
    public function getCompanyId() {
        return $this->companyId;
    }

    /**
     * @inheritdoc
     */
    public function getTokenForRequest(string $key = null, bool $input = false)
    {
        $key = $key ?: $this->inputKey;

        $token = $this->request->headers->get($key);

        if (empty($token)) {
            $token = $this->request->cookie($key);
        }

        if (empty($token) && $input) {
            $token = $this->request->input($key);
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
       return implode('-', [
            $this->storageKey,
            $this->tokenId
        ]);
    }

    /**
     * Get token payload
     */
    private function getPayload(): array
    {
        $payload = [
            'jti' => $this->tokenId,
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

    /**
     * Set company Id
     * 
     */
    public function setCompany(int $id) {

        if ($this->companyId != $id) {
            $this->accessToken = null;
        }

        $this->companyId = $id;

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