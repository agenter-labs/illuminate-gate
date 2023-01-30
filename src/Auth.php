<?php

namespace AgenterLab\Gate;

class Auth
{
    /**
     * @param string $issuer
     * @param string $key
     */
    public function __construct(
        private string $issuer,
        private ?object $payload = null
    ) {
    }
    
    /**
     * @return string|init|null
     */
    public function user()
    {
        return $this->payload?->sub ?? null;
    }

    /**
     * @return string
     */
    public function issuer()
    {
        return $this->issuer;
    }

    /**
     * @return string|init|null
     */
    public function serviceUser()
    {
        return $this->payload?->aud ?? null;
    }
    
    /**
     * @return string|init|null
     */
    public function organization()
    {
        return $this->payload?->org ?? null;
    }

    /**
     * Dynamically retrieve attributes on the payload.
     *
     * @param  string  $key
     * @return mixed
     */
    public function __get($key)
    {
        return $this->payload?->$key ?? null;
    }
}
