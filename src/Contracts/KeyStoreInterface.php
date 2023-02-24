<?php

namespace AgenterLab\Gate\Contracts;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

interface KeyStoreInterface
{
    /**
     * Get secret key
     * 
     * @param string|int $keyId
     * 
     * @return string|resource|OpenSSLAsymmetricKey|OpenSSLCertificate $key The secret key.
     */
    public function getKey(string|int $keyId);
}
