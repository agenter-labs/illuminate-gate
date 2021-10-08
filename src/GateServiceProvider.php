<?php

namespace AgenterLab\Gate;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class GateServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app['auth']->provider('generic', function() {
            return new GenericUserProvider;
         });
         
        $this->app['auth']->extend('token', function () {
            $config =  $this->app['config']['gate.guards.api'];
            $guard = new TokenGuard(
                $this->app['auth']->createUserProvider(
                    $config['provider'] ?? null
                ), 
                $this->app['request'],
                $this->app['config']->get('gate.input_key', 'api-token'),
                $this->app['config']->get('gate.storage_key', 'api_token'),
                $config['hash'] ?? false
            );
            $guard->setTokenManager(app('token.manager'));
            
            return $guard;
        });

        $this->mergeConfigFrom(__DIR__ . '/../config/gate.php', 'gate');
    }

    /**
     * Boot the authentication services for the application.
     *
     * @return void
     */
    public function boot()
    {
        // Here you may define how you wish users to be authenticated for your Lumen
        // application. The callback which receives the incoming request instance
        // should return either a User instance or null. You're free to obtain
        // the User instance via an API token or any other method necessary.

        
    }
}
