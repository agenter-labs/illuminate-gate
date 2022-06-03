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
     * @return \Illuminate\Http\Response
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        $secure = config('gate.cookie.secure');
        $sameSite = config('gate.cookie.same_site');

        $response->withoutCookie(
            Cookie::create(
                config('gate.access_token_name'), 
                null, 
                -2628000
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );
        
        $response->withoutCookie(
            Cookie::create(
                config('gate.id_token_name'), 
                null, 
                -2628000
            )->withSecure($secure)->withSameSite($sameSite)->withRaw()
        );

        return $response;
    }
}