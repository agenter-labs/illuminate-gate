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
     * @param  string|null  $guard
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next, ?string $guard = null)
    {
        $response = $next($request);

        $token =  $this->guard($guard)->getAccessToken();

        if (!$token) {
            return $response;
        }

        $secure = config('gate.cookie.secure');
        $sameSite = config('gate.cookie.same');

        $response->withCookie(
            Cookie::create(
                $this->guard($guard)->getInputKey(), 
                $token->toString(), 
                $token->exp
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );
    
        return $response;
    }

    /**
     * @return \AgenterLab\Gate\JwtGuard
     */
    protected function guard($guard = null)
    {
        return auth($guard);
    }
}