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
     * @param  string|null  $guard
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next, string $claim, string $key = 'app-token', ?string $guard = null)
    {
        $this->validate($request, $claim, $key, $guard);
        
        return $next($request);
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \string $claim
     * @param \string $key
     * @param  string|null  $guard
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function validate($request, string $claim, string $key, ?string $guard = null)
    {
        $jwt = $request->headers->get($key);

        if (empty($jwt)) {
            $jwt = $request->cookie($key);
        }

        if (!$jwt) {
            $jwt = $request->post($key);
        }

        if (!$jwt) {
            throw new \InvalidArgumentException('Token missing');
        }

        $val = $this->guard($guard)->getGate()->validate($jwt)?->{$claim};

        if (!$val) {
            throw new AuthenticationException('Unauthenticated claim.');
        }

        return $val;
    }

    /**
     * @return \AgenterLab\Gate\JwtGuard
     */
    protected function guard($guard = null)
    {
        return auth($guard);
    }
}