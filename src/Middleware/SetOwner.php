<?php

namespace AgenterLab\Gate\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\Cookie;
use Illuminate\Auth\AuthenticationException;

class SetOwner
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
    public function handle($request, Closure $next, $strict = 'normal')
    {
        $response = $next($request);

        if (auth()->isLoggedIn()) {
            $this->checkToken($request);
        }

        if ($strict == 'strict' && !auth()->owner()) {
            throw new AuthenticationException('Unauthenticated owner.');
        }

        return $next($request);
    }

    /**
     * Check token
     */
    private function checkToken($request)
    {
        $tokenName = config('gate.owner_token_name');

        $token = $request->headers->get($tokenName);
        
        if (empty($token)) {
            $token = $request->cookie($tokenName);
        }
        
        if (!$token) {
            return false;
        }

        $tknParts = explode('-', $token);

        $owner = array_pop($tknParts);

        $parts = [auth()->id()];
        $companyId = auth()->companyId();
        if ($companyId) {
            $parts[] = $companyId;
        }

        $payload = implode('_', $parts);

        $ownerData = hash_hmac('sha256', $payload, $owner);

        if ($ownerData == implode('', $tknParts)) {
            auth()->setOwner(hexdec($owner));
        }

        return false;
    }
}