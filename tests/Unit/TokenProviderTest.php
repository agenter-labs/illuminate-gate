<?php

namespace Tests\Unit;

use Tests\TestCase;
use AgenterLab\Gate\TokenProvider;
use AgenterLab\Gate\KeyStores\FileKeyStore;

class TokenProviderTest extends TestCase
{

    public function testSymmetric()
    {
        $provider = new TokenProvider(
            new FileKeyStore('/var/www/html/tests/keys')
        );

        // Encoding
        $token = $provider->encode('gate', ['sub' => 25], 'HS256', 600);
        $this->assertEquals($token->getAlgorithm(), 'HS256');
        $this->assertEquals($token->sub, 25);

        // Decoding
        $token = $provider->decode($token->toString());
        $this->assertEquals($token->getAlgorithm(), 'HS256');
        $this->assertEquals($token->sub, 25);
    }

    public function testAsymmetric()
    {
        $provider = new TokenProvider(
            new FileKeyStore('/var/www/html/tests/keys')
        );

        // Encoding
        $token = $provider->encode('test-rsa', ['sub' => 25], 'RS256', 600);
        $this->assertEquals($token->getAlgorithm(), 'RS256');
        $this->assertEquals($token->sub, 25);

        // Decoding
        $token = $provider->decode($token->toString());
        $this->assertEquals($token->getAlgorithm(), 'RS256');
        $this->assertEquals($token->sub, 25);
    }
}