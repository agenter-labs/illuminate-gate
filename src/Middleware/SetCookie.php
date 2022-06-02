<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\Cookie;

class SetCookie
{

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string[]  ...$guards
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        if (!auth()->isLoggedIn()) {
            return $response;
        }

        $secure = config('gate.cookie.secure');
        $sameSite = config('gate.cookie.same_site');
        
        $token =  auth()->getTokenArray();
        $expires =  auth()->->expireIn();

        $owner = auth()->owner();

        $response->withCookie(
            Cookie::create(
                config('gate.input_key'), 
                $token->getToken(), 
                $expires
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );
        
        if ($owner) {

            $owner = dechex($owner);
            $ownerData = hash_hmac('sha256', $token->getPayload(), $owner);

            $response->withCookie(
                Cookie::create(
                    config('gate.owner_token_name'),
                    chunk_split($ownerData, strlen($owner), "-") . $owner,
                    $expires
                )->withSecure($secure)->withSameSite($sameSite)->withRaw()
            );
        }

        return $response;
    }
}