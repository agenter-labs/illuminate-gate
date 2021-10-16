<?php

namespace AgenterLab\Gate\Middleware;

use Closure;

class ClearCredentials
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

        foreach($request->cookies->keys() as $key) {
            $response->withoutCookie($key);
        }

        return $response;
    }
}