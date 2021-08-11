<?php

namespace AgenterLab\Gate;

use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;

class TokenGuard
{
    use GuardHelpers;


    /**
     * The event dispatcher instance.
     *
     * @var \AgenterLab\Gate\TokenManager
     */
    protected $tokenManager;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * The name of the query string item from the request containing the API token.
     *
     * @var string
     */
    protected $inputKey;

    /**
     * The name of the token "column" in persistent storage.
     *
     * @var string
     */
    protected $storageKey;

    /**
     * Indicates if the API token is hashed in storage.
     *
     * @var bool
     */
    protected $hash = false;

    /**
     * Create a new authentication guard.
     *
     * @param  \AgenterLab\Gate\TokenManager;  $tokenManager
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $inputKey
     * @param  string  $storageKey
     * @param  bool  $hash
     * @return void
     */
    public function __construct(
        TokenManager $tokenManager,
        Request $request,
        $inputKey = 'api_token',
        $storageKey = 'api_token',
        $hash = false)
    {
        $this->hash = $hash;
        $this->request = $request;
        $this->tokenManager = $tokenManager;
        $this->inputKey = $inputKey;
        $this->storageKey = $storageKey;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
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

        $token = $this->getTokenForRequest();
        
        if (! empty($token)) {

            list($tokenId, $tokenUserId) = $this->tokenManager->validate('access_token', $token, false);

            // $user = $this->provider->retrieveById($tokenUserId[0]);

            $user = (object)[
                'id' => $tokenUserId[0],
                'tokenId' => $tokenId
            ];
        }

        return $this->user = $user;
    }


    /**
     * @inheritdoc
     */
    public function getTokenForRequest()
    {
        $token = $this->request->query($this->inputKey);

        if (empty($token)) {
            $token = $this->request->input($this->inputKey);
        }

        if (empty($token)) {
            $token = $this->request->bearerToken();
        }

        if (empty($token)) {
            $token = $this->request->getPassword();
        }

        if (empty($token)) {
            $token = $this->request->headers->get($this->inputKey);
        }

        return $token;
    }
}