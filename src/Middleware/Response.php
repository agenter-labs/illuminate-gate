<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\Cookie;

class Response
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

        $token =  auth()->getAccessToken();
        if (!$token) {
            return $response;
        }

        $secure = config('gate.cookie.secure');
        $sameSite = config('gate.cookie.same_site');

        $response->withCookie(
            Cookie::create(
                config('gate.access_token_name'), 
                $token->getToken(), 
                $token->getValiditiy()
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );
    
        return $response;
    }
}