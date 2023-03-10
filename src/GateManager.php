<?php

namespace AgenterLab\Gate;

use Illuminate\Support\Facades\Cache;
use InvalidArgumentException;
use Closure;

class GateManager
{
    /**
     * The array of resolved key stores.
     *
     * @var Contracts\KeyStoreInterface[]
     */
    protected $keyStores = [];

    /**
     * The registered custom key creators.
     *
     * @var array
     */
    protected $customKeyStores = [];

    /**
     * The gates.
     *
     * @var Gate[]
     */
    protected $gates = [];

    /**
     * Create a new Gate manager instance.
     *
     * @param \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public function __construct(protected $app)
    {
    }

    /**
     * Get gate instance
     *
     * @param string $name
     * 
     * @return Gate
     */
    public function get(?string $name = null)
    {
        $name = $name ?: $this->getDefaultGate();

        return $this->gates[$name] = $this->getGate($name);
    }

    /**
     * Attempt to get the gate from the local cache.
     *
     * @param  string  $name
     * @return Gate
     */
    protected function getGate($name)
    {
        return $this->gates[$name] ?? $this->resolveGate($name);
    }

    /**
     * Resolve the given store.
     *
     * @param  string  $name
     * @return Gate
     *
     * @throws \InvalidArgumentException
     */
    protected function resolveGate($name)
    {
        $config = $this->getGateConfig($name);

        if (is_null($config)) {
            throw new InvalidArgumentException("Gate [{$name}] is not defined.");
        }

        return new Gate(
            new TokenProvider($this->keyStore($config['key-store'] ?? null)),
            Cache::store($config['storage']),
            $config['storage-key'],
            $config['issuer'] ?? $this->app['config']['gate.issuer'],
            $config['alg'] ?? $this->app['config']['gate.alg'],
            $config['ttl'] ?? $this->app['config']['gate.ttl'],
        );
    }

    /**
     * Get a cache store instance by name, wrapped in a repository.
     *
     * @param  string|null  $name
     * @return Contracts\KeyStoreInterface
     */
    public function keyStore($name = null)
    {
        $name = $name ?: $this->getDefaultKeyStore();

        return $this->keyStores[$name] = $this->getKeyStore($name);
    }

    /**
     * Attempt to get the store from the local cache.
     *
     * @param  string  $name
     * @return \Illuminate\Contracts\Cache\Repository
     */
    protected function getKeyStore($name)
    {
        return $this->keyStores[$name] ?? $this->resolveKeyStore($name);
    }

    /**
     * Resolve the given store.
     *
     * @param  string  $name
     * @return \Illuminate\Contracts\Cache\Repository
     *
     * @throws \InvalidArgumentException
     */
    protected function resolveKeyStore($name)
    {
        $config = $this->getKeyStoreConfig($name);

        if (is_null($config)) {
            throw new InvalidArgumentException("Gate key store [{$name}] is not defined.");
        }

        if (isset($this->customKeyStores[$config['driver']])) {
            return $this->callCustomKeyStore($name, $config);
        } else {
            $driverMethod = 'create' . ucfirst($config['driver']) . 'KeyStore';

            if (method_exists($this, $driverMethod)) {
                return $this->{$driverMethod}($name, $config);
            } else {
                throw new InvalidArgumentException("Driver [{$config['driver']}] is not supported.");
            }
        }
    }

    /**
     * Call a custom key store creator.
     *
     * @param  string  $name
     * @param  array  $config
     * @return Contracts\KeyStoreInterface
     */
    protected function callCustomKeyStore($name, $config)
    {
        return $this->customKeyStores[$config['driver']]($name, $config);
    }

    /**
     * Create a array key store
     *
     * @param  string  $name
     * @param  array  $config
     * @return KeyStores\ArrayKeyStore
     */
    public function createArrayKeyStore($name, $config)
    {
        return new KeyStores\ArrayKeyStore();
    }

    /**
     * Create a File key store
     *
     * @param  string  $name
     * @param  array  $config
     * @return KeyStores\FileKeyStore
     */
    public function createFileKeyStore($name, $config)
    {
        return new KeyStores\FileKeyStore($config['path']);
    }

    /**
     * Get the key store configuration.
     *
     * @param  string  $name
     * @return array
     */
    protected function getKeyStoreConfig($name)
    {
        return $this->app['config']["gate.key-stores.{$name}"];
    }
    
    /**
     * Get the default key store name.
     *
     * @return string
     */
    public function getDefaultKeyStore()
    {
        return $this->app['config']['gate.defaults.key-store'];
    }

    /**
     * Get the default gate name.
     *
     * @return string
     */
    public function getDefaultGate()
    {
        return $this->app['config']['gate.defaults.guard'];
    }

    /**
     * Get the key store configuration.
     *
     * @param  string  $name
     * @return array
     */
    protected function getGateConfig($name)
    {
        return $this->app['config']["gate.guards.{$name}"];
    }

    /**
     * Register a custom driver creator Closure.
     *
     * @param  string  $driver
     * @param  \Closure  $callback
     * @return $this
     */
    public function extend($driver, Closure $callback)
    {
        $this->customKeyStores[$driver] = $callback;

        return $this;
    }
}
