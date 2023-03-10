<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Auth\TokenGuard;

class JwtGuard extends TokenGuard
{

    /**
     * @var int
     */
    private ?int $organizationId = null;

    /**
     * Unique id accross all apps
     * 
     * @var int
     * 
     */
    private ?int $accountId = null;

    const SLEEP_TIME = 300;

    /**
     * Create a new authentication guard.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $inputKey
     * @return void
     */
    public function __construct(
        protected string $name,
        protected Gate $gate,
        protected string $claim,
        protected bool $strict,
        UserProvider $provider,
        Request $request,
        string $inputKey = 'gate-token'
    ) {
        parent::__construct($provider, $request, $inputKey);
    }

    /**
     * Get the currently authenticated user.
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $jwt = $this->getTokenForRequest();

        if (!empty($jwt)) {

            $accessToken = $this->gate->validate($jwt, $this->strict);
            if ($accessToken) {
                $this->user = $this->provider->retrieveById($accessToken->{$this->claim});
                $this->organizationId = $accessToken->org;
    
                if ($this->claim == 'aud') {
                    $this->accountId = $accessToken->sub;
                }
            }
        }

        return $this->user;
    }

    public function getAccessToken()
    {
        if (!$this->id()) {
            return;
        }

        $token = $this->gate->getToken();
        $issueToken = false;
        if ($token) {
            if (
                $this->inRenewalPeriod() ||
                $this->id() != $token->{$this->claim} ||
                $this->accountId != $token->sub ||
                $this->organizationId != $token->org
            ) {
                $issueToken = true;
            }
        } else {
            $issueToken = true;
        }

        if ($issueToken) {
            $this->gate->issueToken($this->getPayload(), strict: $this->strict);
        }

        return $this->gate->getToken();
    }

    /**
     * @return bool
     */
    private function inRenewalPeriod()
    {

        $expired = $this->gate->getToken()->expired(self::SLEEP_TIME);

        if ($expired) {
            $this->refreshToken();
        }

        return $expired;
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
    public function refreshToken()
    {

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
        if ($this->id()) {
            $this->gate->clear();
        }
    }

    /**
     * Get token key
     */
    private function tokenKey(): string
    {
        return implode('-', [$this->storageKey, $this->gate->getToken()?->jti]);
    }

    /**
     * Get token payload
     */
    protected function getPayload(): array
    {
        $payload = [
            'jti' => $this->gate->getToken()?->jti,
            $this->claim => $this->id()
        ];

        if ($this->accountId) {
            $payload['sub'] = $this->accountId;
        }

        if ($this->organizationId) {
            $payload['org'] = $this->organizationId;
        }

        return $payload;
    }

    /**
     * Set Account Id
     * 
     */
    public function setAccount(int $id)
    {

        $this->accountId = $id;

        return $this;
    }

    /**
     * Set organization Id
     * 
     */
    public function setOrganization(int $id)
    {

        $this->organizationId = $id;

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
        $this->user = $user;

        return $this;
    }

    /**
     * Get account id
     */
    public function getAccountId()
    {
        return $this->accountId;
    }

    /**
     * Get Organization id
     */
    public function getOrganizationId()
    {
        return $this->organizationId;
    }

    /**
     * Get input Key
     * 
     * @return string
     */
    public function getInputKey()
    {
        return $this->inputKey;
    }

    /**
     * Get gate
     * 
     * @return Gate
     */
    public function getGate()
    {
        return $this->gate;
    }
}
