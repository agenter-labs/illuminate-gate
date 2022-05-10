<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\Cookie;

class SetCookieCredentials
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
        
        $token =  auth()->getToken();
        $expires =  $token->getExpireIn();

        $owner = auth()->owner();

        $response->withCookie(
            Cookie::create(
                config('gate.input_key'), 
                $token->getToken(), 
                $expires
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );
        
        if ($owner) {
            $response->withCookie(
                Cookie::create(
                    config('gate.owner_token_name'),
                    base64_encode($owner), 
                    $expires
                )->withSecure($secure)->withSameSite($sameSite)->withRaw()
            );
        }

        return $response;
    }
}