<?php

namespace Tests\Feature;

use Tests\TestCase;
use AgenterLab\AGWS\Client;
use Firebase\JWT\JWT;
use AgenterLab\Gate\TokenGuard;

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

        echo $token = $this->getToken($user, $serviceUser, $organization);

        $this->get('user', [
            config('gate.access_token_name') => $token
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

        $this->get('login', [
            config('gate.access_token_name') => $token
        ])
        ->seeJsonStructure(['token', 'ttl', 'expire_in']);
    }

    private function getToken($user, $serviceUser, $organization)
    {
        return JWT::encode(
            [
                'exp' => time() + config('gate.ttl'),
                'aud' => $serviceUser,
                'sub' => $user,
                'org' => $organization,
            ], 
            config('gate.secrete_key'), 
            TokenGuard::ALGO
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