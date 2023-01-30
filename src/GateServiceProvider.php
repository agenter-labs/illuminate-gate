<?php

namespace AgenterLab\Gate;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Auth;

class GateServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('gate', function ($app) {
            return new Gate(
                new TokenProvider(
                    $app['config']->get('gate.key-path'),
                    $app['config']->get('gate.algo'),
                    $app['config']->get('gate.ttl')
                )
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
        Auth::provider('generic', function() {
            return new GenericUserProvider;
        });
         
        Auth::extend('token', function () {
            return new JwtGuard(
                $this->app->make('cache')->driver(
                    $this->app['config']->get('gate.store')
                ),
                $this->app['gate'],
                $this->app['config']->get('gate.user-claim'),
                $this->app['config']->get('gate.issuer'),
                $this->app['config']->get('gate.strict'),
                $this->app['auth']->createUserProvider(
                    $this->app['config']->get('gate.provider'),
                ), 
                $this->app['request'],
                $this->app['config']->get('gate.access-token-name'),
                $this->app['config']->get('gate.storage-key')
            );
        });
    }
}
