<?php

namespace AgenterLab\Gate;

use Illuminate\Support\Facades\Auth;
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
        $this->mergeConfigFrom(__DIR__ . '/../config/gate.php', 'gate');
        
        $this->registerGate();
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
                $config['token-name'] ?? 'gate-token'
            );
        });
    }
}
