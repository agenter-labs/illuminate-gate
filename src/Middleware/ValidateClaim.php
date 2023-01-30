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
     * @param string|null  $algo
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next, string $claim, ?string $algo = null)
    {
        $jwt = $this->guard()->getTokenForRequest('app-token');

        if (!$jwt) {
            $jwt = $request->input('app-token');
        }

        if (!$jwt) {
            throw new \InvalidArgumentException('Token missing');
        }

        $val = $this->gate()->validate($jwt, $algo)->auth()->{$claim};

        if (!$val) {
            throw new AuthenticationException('Unauthenticated.');
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