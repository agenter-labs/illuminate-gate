<?php

namespace Tests\Feature;

use Tests\TestCase;
use Firebase\JWT\JWT;
use AgenterLab\Gate\JwtGuard;

class ClinetTest extends TestCase
{

    public function testWithoutToken()
    {
        $this->expectException(\Illuminate\Auth\AuthenticationException::class);
        $this->get('user')
        ->seeJson([
            'id' => null
        ]);
    }

    /**
     * @dataProvider providesToken
     */
    public function testToken($user, $serviceUser, $organization)
    {
        $token = $this->getToken($user, $serviceUser, $organization);

        $this->get('user', [
            config('gate.token-name') => $token
        ])
        ->seeJson([
            'id' => $serviceUser,
            'sub' => $user,
            'org' => $organization,
        ]);
    }

    /**
     * @dataProvider providesToken
     */
    public function testTokenResponse($user, $serviceUser, $organization)
    {

        $token = $this->getToken($user, $serviceUser, $organization);

        $this->get('token', [
            config('gate.token-name') => $token
        ])
        ->seeJsonStructure(['token', 'ttl', 'expire_in']);
    }

    public function testCookieSet()
    {

        $token = $this->getToken(1, 1, 1);

        $this->get('login', [
            config('gate.token-name') => $token
        ]);
        $this->response->assertCookieNotExpired(config('gate.token-name'));
    }

    public function testCookieDelete()
    {

        $token = $this->getToken(1, 1, 1);

        $this->call('GET', 'logout', [], [
            config('gate.token-name') => $token
        ]);
        $this->seeJsonStructure(['token', 'ttl', 'expire_in']);
    
        $this->assertEquals(0,
            $this->response->getCookie(config('gate.token-name'), false)
            ->getExpiresTime()
        );
    }

    public function testClaimMiddleware()
    {
        $jwt = JWT::encode(
            [
                'iss' => 'id',
                'exp' => time() + config('gate.ttl'),
                'jti' => time(),
                'sub' => 10,
            ], 
            'abc1245xyzid', 
            config('gate.alg'),
            'id'
        );

        $this->call('POST', 'claim', ['app-token' => $jwt]);
        $this->seeStatusCode(200)
            ->seeJsonEquals(['sub' => 10]);
    }

    private function getToken($user, $serviceUser, $organization)
    {
        return JWT::encode(
            [
                'iss' => 'gate',
                'exp' => time() + config('gate.ttl'),
                'jti' => time(),
                'aud' => $serviceUser,
                'sub' => $user,
                'org' => $organization,
            ], 
            'abc1245xyz', 
            config('gate.alg')
        );
    }

    public function providesToken()
    {
        return [
            [1, 1, 1],
            [1568, 1, 156],
        ];
    }

}