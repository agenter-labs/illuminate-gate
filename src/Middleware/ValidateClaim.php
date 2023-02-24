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
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next, string $claim, string $key = 'app-token')
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

        $val = $this->gate()->validate($jwt)->{$claim};

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
}