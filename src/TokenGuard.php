<?php

namespace AgenterLab\Gate;

use AgenterLab\Token\TokenManager;
use Illuminate\Support\Facades\Http;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;

class TokenGuard extends \Illuminate\Auth\TokenGuard
{
    /**
     *
     * @var \AgenterLab\Token\TokenManager
     */
    protected $tokenManager;

    /**
     *
     * @var \AgenterLab\Token\Token
     */
    protected $token;

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
     * Check user logged in
     * 
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return !is_null($this->user);
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return $this
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        $this->token = null;

        return $this;
    }

    /**
     * Get the currently authenticated user.
     *
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        // $this->checkAccount();

        $token = $this->getTokenForRequest();
    
        if (! empty($token)) {
            $this->token = $this->tokenManager->validate('access-token', $token, '', true);
            $payload = explode('_', $this->token->getPayload());
            $userId = $payload[0];
            $user = $this->provider->retrieveById($userId);

            if ($user && !$this->accountId) {
                $this->accountId = $user->account_id ?? null;
            }

            if ($user && !empty($payload[1])) {
                $this->companyId = $payload[1];
            }
        }
        

        return $this->user = $user;
    }

    /**
     * Get the currently authenticated user.
     *
     */
    public function accountUser()
    {
        $accountId = $this->account();

        if ($accountId && is_null($this->user)) {
            $this->user = $this->provider->retrieveByCredentials(['account_id' => $accountId]);
        }

        return $this->user;
    }

    /**
     * Get the currently authenticated user.
     *
     */
    public function createAccountUser()
    {
        $accountId = $this->account();

        if (!$accountId) {
            throw new \UnexpectedValueException('Must provide valid account id', 403);
        }

        $response = Http::withHeaders([
            'client-secrete' => env('AUTH_CLIENT_SECRETE'),
            'client-id' => env('AUTH_CLIENT_ID')
        ])->acceptJson()
        ->get(env('AUTH_ID_SERVICE') . '/client/profile/' . $this->account());

        if ($response->successful()) {
            // $this->user = $this->provider->createModel()::create([
            //     'account_id' => $this->account(),
            //     'name' => $response['display_name'],
            //     'email' => $response['email'],
            //     'country' => $response['country'],
            //     'name' => $response['display_name']
            // ]);
        }
    }

    /**
     * Log a user into the application using account id
     *
     * @return bool
     */
    public function serviceLogin()
    {
        if (! is_null($this->user)) {
            return true;
        }

        $accountId = $this->account();

        if (!$accountId) {
            return false;
        }

        $user = $this->provider->retrieveByCredentials(['account_id' => $accountId]);

        if ($user) {
            $this->setUser($user);
            return true;
        }

        return false;
    }

    
    public function getToken() {

        $userId = $this->user ? $this->user->id : null;

        if (!$userId || !$this->accountId) {
            throw new \UnexpectedValueException('Unable to issue token, request not authenticated', 403);
        }

        if ($this->companyId) {
            $userId .= '_' . $this->companyId;
        }
        
        if (!$this->token) {
            $this->token = $this->tokenManager->create('access-token', $userId, '', $this->accountId);
        }

        return $this->token;
    }

    /**
     * Get account
     */
    public function account() {
        $this->checkAccount();
        return $this->accountId;
    }

    /**
     * Get company Id
     * 
     * @return int
     */
    public function companyId() {
        return $this->companyId;
    }

    /**
     * Set company Id
     * 
     */
    public function setCompany(int $companyId) {
        $this->companyId = $companyId;

        $this->token = null;

        return $this;
    }

    
    /**
     * Check identity
     */
    private function checkAccount() {

        if (! is_null($this->accountId)) {
            return $this->accountId;
        }

        $name = config('gate.app_token_name');
        if (!$name) {
            return false;
        }

        $token = $this->request->headers->get($name);
        
        if (empty($token)) {
            $token = $this->request->cookie($name);
        }

        if (empty($token)) {
            $token = $this->request->input($name);
        }

        if (!$token) {
            return false;
        }

        $token = $this->tokenManager->validate('service-token', $token, config('gate.secrete_key'));

        $this->accountId = $token->getPayload();
        return (bool)$token->getId();
    }

    /**
     * Set the token manager instance.
     *
     * @param  \AgenterLab\Token\TokenManager  $tokenManager
     * @return void
     */
    public function setTokenManager(TokenManager $tokenManager)
    {
        $this->tokenManager = $tokenManager;
    }

    /**
     * @inheritdoc
     */
    public function getTokenForRequest()
    {
        $token = parent::getTokenForRequest();

        if (empty($token)) {
            $token = $this->request->headers->get($this->inputKey);
        }

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
        $user = $this->user();

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
        $user = $this->user();

        if ($this->token) {
            $this->tokenManager->remove('access-token' . '_' . $this->token->getId());
        }
        
        $this->token = null;
    }

    /**
     * Set account
     */
    public function setAccount($accountId = null) {
        $this->accountId = $accountId;
    }

}