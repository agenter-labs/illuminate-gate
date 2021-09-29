<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\Cookie;

class SetCredentials
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
        
        $token =  auth()->getToken();
        $expires =  $token->getExpireIn();

        return $response->withCookie(
            Cookie::create(
                config('gate.input_key'), 
                $token->getToken(), 
                $expires
            )->withSecure()->withRaw()
        );
    }
}