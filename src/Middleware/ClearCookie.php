<?php

namespace AgenterLab\Gate\Middleware;

use Closure;

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

        $response->withoutCookie(config('gate.access_token_name'));

        return $response;
    }
}