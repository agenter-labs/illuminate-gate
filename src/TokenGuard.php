<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Cache\Repository;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
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
        private string $idStorageKey,
        private string $idProviderKey,
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

    /**
     * ID login
     * Login using token from id provider
     */
    public function idTokenLogin()
    {
        if ($this->check()) {
            return true;
        }

        if (!$this->accountId) {
            $this->verifyIdToken();
        }

        if (!$this->accountId) {
            return false;
        }

        $this->user = $this->provider->retrieveByCredentials(['account_id' => $this->accountId]);

        $this->jwtToken = null;
        
        return $this->check();
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
        
        $decoded = JWT::decode($token, new Key($this->idProviderKey, self::ALGO));

        $this->accountId = $decoded?->sub;
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

        $this->refreshExpiring();

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

    private function refreshExpiring() {

        if (!$this->tokenExp) {
            return;
        }

        if (($this->tokenExp - self::SLEEP_TIME) <= time()) {
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

    public function expireIn() {
        return $this->tokenExp;
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
            $this->repository->delete($this->tokenKey());
        }

        $this->jwtToken = null;
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

    /**
     * Set company Id
     * 
     */
    public function setCompany(int $id) {

        if ($this->companyId != $id) {
            $this->jwtToken = null;
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
            $this->jwtToken = null;
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
        $_id = $this->id();

        $this->user = $user;

        $id = $this->id();

        if ($id != $_id) {
            $this->jwtToken = null;
        }

        return $this;
    }
}