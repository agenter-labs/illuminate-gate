<?php

namespace AgenterLab\Gate;

interface TokenRepositoryInterface
{
    /**
     * Create a new token.
     *
     * @param \AgenterLab\Gate\TokenClaim  $claim
     * 
     * @return int|string
     */
    public function create(TokenClaim $claim): int|string;

    /**
     * Delete a token record by user.
     *
     * @param int|string $id
     * @return void
     */
    public function delete(int|string $id);
}
