<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\Cookie;

class ClearCookie
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return \Illuminate\Http\Response
     */
    public function handle($request, Closure $next, ?string $guard = null)
    {
        $response = $next($request);

        $secure = config('gate.cookie.secure');
        $sameSite = config('gate.cookie.same');

        $response->withoutCookie(
            Cookie::create(
                $this->guard($guard)->getInputKey(), 
                null, 
                -2628000
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