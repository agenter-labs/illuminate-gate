<?php

namespace AgenterLab\Gate\KeyStores;

use AgenterLab\Gate\Contracts\KeyStoreInterface;

class FileKeyStore implements KeyStoreInterface
{
    /**
     * @var string[]
     */
    private array $keys = [];

    /**
     * @param string $keyPath
     */
    public function __construct(private string $keyPath) {
    }

    /**
     * @inheritdoc
     */
    public function getKey(string|int $keyId)
    {

        if (empty($this->keys[$keyId])) {

            $pkPath = $this->keyPath . '/' . $keyId;

            if (!is_file($pkPath)) {
                throw new \InvalidArgumentException('Invalid key path: ' . $pkPath);
            }

            $this->keys[$keyId] = file_get_contents($pkPath);
        }

        return $this->keys[$keyId];
    }
}
