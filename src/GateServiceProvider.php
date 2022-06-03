<?php

namespace AgenterLab\Gate;

use Illuminate\Support\ServiceProvider;

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
            return new TokenGuard(
                $this->app->make('cache')->driver(
                    $this->app['config']->get('gate.store')
                ),
                $this->app['config']->get('gate.ttl'),
                $this->app['config']->get('gate.secrete_key'),
                $this->app['config']->get('gate.strict'),
                $this->app['config']->get('gate.id_token_name'),
                $this->app['config']->get('gate.id_provider_key'),
                $this->app['auth']->createUserProvider(
                    $this->app['config']->get('gate.provider'),
                ), 
                $this->app['request'],
                $this->app['config']->get('gate.access_token_name')
            );
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
