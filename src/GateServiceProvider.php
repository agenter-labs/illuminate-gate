<?php

namespace AgenterLab\Gate;

use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\AuthServiceProvider as ServiceProvider;

class GateServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        parent::register();

        $this->registerGate();

        $this->mergeConfigFrom(__DIR__ . '/../config/gate.php', 'gate');
    }

    /**
     * Register gate
     *
     * @return void
     */
    protected function registerGate()
    {
        $this->app->singleton('gate', fn ($app) => new GateManager($app));
    }

    /**
     * Boot the authentication services for the application.
     *
     * @return void
     */
    public function boot()
    {
        Auth::provider('generic', fn () => new GenericUserProvider);

        Auth::extend('jwt', function ($app, $name, $config) {
            return new JwtGuard(
                $name,
                $app['gate']->get($config['gate'] ?? null),
                $config['user-claim'] ?? 'sub',
                $config['strict'] ?? false,
                Auth::createUserProvider($config['provider']),
                $app['request'],
                $config['token-name'] ?? 'access-token'
            );
        });
    }
}
