<?php

namespace AgenterLab\Gate;

use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app['auth']->extend('token', function () {
            $config =  $this->app['config']['gate.guards.api'];
            $guard = new \App\Auth\TokenGuard(
                app(\App\Token\TokenManager::class), 
                $this->app['request'],
                $config['input_key'] ?? 'api-token',
                $config['storage_key'] ?? 'api_token',
                $config['hash'] ?? false
            );
            return $guard;
        });
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
