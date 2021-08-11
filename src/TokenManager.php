<?php

namespace AgenterLab\Gate;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;

class TokenManager
{
    
    /**
     * @var Illuminate\Contracts\Cache\Repository
     */
    private $cache;

    /**
     * The Hasher implementation.
     *
     * @var \Illuminate\Contracts\Hashing\Hasher
     */
    protected $hasher;

    /**
     * The hashing key.
     *
     * @var string
     */
    protected $hashKey;

    /**
     * @var array
     */
    private $config;


    function __construct(Repository $cache, HasherContract $hasher, $hashKey, array $config = []) {
        $this->cache = $cache;
        $this->hasher = $hasher;
        $this->hashKey = $hashKey;
        $this->config = $config;
    }

    /**
     * Validate token 
     * 
     * @param string $type
     * @param string $token
     * @param bool $strict Check in cache
     * 
     * @return mixed
     */
    public function validate(string $type, string $token, bool $strict = false) {

        $decrypted = app('encrypter')->decryptString(self::decodeUrlSafe($token));

        $tokenParts = explode('|', $decrypted);
        $expireAt = array_pop($tokenParts);
        $tokenType = array_pop($tokenParts);
        $tokenId = array_pop($tokenParts);

        if ($type != $tokenType) {
            throw new AuthorizationException('Token type invalid');
        }

        if (time() > $expireAt) {
            throw new AuthorizationException('expired');
        }

        if ($strict) {

            $exists = $this->cache->get($type . '_' . $tokenId);

            if (empty($exists)) {
                throw new AuthorizationException('Token invalid');
            }
        }

        return [$tokenId, $tokenParts];

    }

    /**
     * Remove token
     * 
     * @param string $key
     */
    public function remove(string $key) {
        $this->cache->forget($key);
    }


     /**
    * Converts a base64 encode url safe
    *
    * @param string $str
    * @return string
    */

    public static function encodeUrlSafe($str)
    {
        return str_replace('=', '', strtr($str, '+/', '-_'));
    }

    /**
    * Converts a base64 decode url safe
    *
    * @param string $str
    * @return string
    */

    public static function decodeUrlSafe($str)
    {
        if ($remainder = strlen($str) % 4) {
            $str .= str_repeat('=', 4 - $remainder);
        }

        $str = strtr($str, '-_', '+/');
        return $str;
    }

    /**
     * Check Hash
     */
    public function check(string $key, string $token) {

        $exists = $this->cache->get($key);

        if (empty($exists)) {
            throw new AuthorizationException('Token does not exist');
        }

        $check = $this->hasher->check($token, $exists);

        if (!$check) {
            throw new AuthorizationException('Token invalid');
        }

        return true;
    }
}