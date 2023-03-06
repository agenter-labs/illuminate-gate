<?php

namespace AgenterLab\Gate\KeyStores;

use AgenterLab\Gate\Contracts\KeyStoreInterface;
use RuntimeException;

class ArrayKeyStore implements KeyStoreInterface
{
    /**
     * @var string[]
     */
    private array $keys = [];

    /**
     * Add new key
     * 
     * @param string|int $keyId
     * @param mixed $keyMaterial
     * 
     * @return void
     */
    public function push(string|int $keyId, $keyMaterial)
    {
        if (array_key_exists($keyId, $this->keys)) {
            throw new RuntimeException("Key allready exists");
        }

        $this->keys[$keyId] = $keyMaterial;
    }

    /**
     * @inheritdoc
     */
    public function getKey(string|int $keyId)
    {
        if (!array_key_exists($keyId, $this->keys)) {
            throw new RuntimeException("Key not exists");
        }

        return $this->keys[$keyId];
    }
}
