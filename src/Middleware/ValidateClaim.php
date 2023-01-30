<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;

class ValidateClaim
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure  $next
     * @param \string $claim
     * @param \string $key
     * @param string|null  $algo
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next, string $claim, string $key = 'app-token', ?string $algo = null)
    {
        $jwt = $this->guard()->getTokenForRequest($key);

        if (!$jwt) {
            $jwt = $request->input($key);
        }

        if (!$jwt) {
            throw new \InvalidArgumentException('Token missing');
        }

        $val = $this->gate()->validate($jwt, $algo)->{$claim};

        if (!$val) {
            throw new AuthenticationException('Unauthenticated claim.');
        }

        return $next($request);
    }

    /**
     * @return \AgenterLab\Gate\Gate
     */
    protected function gate()
    {
        return app('gate');
    }

    /**
     * @return \AgenterLab\Gate\JwtGuard
     */
    protected function guard()
    {
        return auth();
    }
}