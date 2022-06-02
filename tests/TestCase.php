<?php

namespace Tests;

use Laravel\Lumen\Testing\TestCase as BaseTestCase;
use Laravel\Lumen\Http\Request as LumenRequest;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Illuminate\Testing\TestResponse;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;

    static $KEY_GENERATED = false;


    protected function setUp(): void
    {    
        parent::setUp();
        config([
            'auth.guards.api.driver' => 'token',
            'auth.providers.token' => ['driver' => 'generic']
        ]);
    }
    
    /**
     * Call the given URI and return the Response.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  array  $parameters
     * @param  array  $cookies
     * @param  array  $files
     * @param  array  $server
     * @param  string  $content
     * @return \Illuminate\Http\Response
     */
    public function call($method, $uri, $parameters = [], $cookies = [], $files = [], $server = [], $content = null)
    {
        $this->currentUri = $this->prepareUrlForRequest($uri);

        $symfonyRequest = SymfonyRequest::create(
            $this->currentUri, $method, $parameters,
            $cookies, $files, $server, $content
        );

        $this->app['request'] = LumenRequest::createFromBase($symfonyRequest);

        // $this->app['auth']->setRequest($this->app['request']);

        return $this->response = TestResponse::fromBaseResponse(
            $this->app->prepareResponse($this->app->handle($this->app['request']))
        );
    }
}