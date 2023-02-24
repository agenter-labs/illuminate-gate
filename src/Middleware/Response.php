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

        $token =  $this->guard()->getAccessToken();

        if (!$token) {
            return $response;
        }

        $secure = config('gate.cookie.secure');
        $sameSite = config('gate.cookie.same');

        $response->withCookie(
            Cookie::create(
                config('gate.token-name'), 
                $token->toString(), 
                $token->exp
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );
    
        return $response;
    }

    /**
     * @return \AgenterLab\Gate\JwtGuard
     */
    protected function guard()
    {
        return auth();
    }
}