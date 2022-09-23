<?php
namespace AgenterLab\Gate;

use Illuminate\Support\Facades\DB;

class DatabaseTokenRepository implements TokenRepositoryInterface
{
    /**
     * Create a new token repository instance.
     *
     * @param \Illuminate\Database\ConnectionInterface  $connection
     * @param string $table
     * @param int $expires
     * @return void
     */
    public function __construct(
        protected string $table,
        protected int $expires = 60)
    {
    }

    /**
     * Create a new token record.
     *
     * @param \AgenterLab\Gate\TokenClaim $cliam
     * 
     * @return int|string
     */
    public function create(TokenClaim $cliam): int|string
    {
        $payload = $this->getPayload($cliam);

        DB::table($this->table)->insert($payload);

        return $payload['id'];
    }

    /**
     * Delete a token record by user.
     *
     * @param int|string $id
     * @return void
     */
    public function delete(int|string $id)
    {
        return DB::table($this->table)->where('id', $id)->delete();
    }

    /**
     * Build the record payload for the table.
     *
     * @param \AgenterLab\Gate\TokenClaim $cliam
     * @return array
     */
    protected function getPayload(TokenClaim $cliam)
    {
        return [
            'id' => app(\AgenterLab\Uid\Uid::class)->create(),
            'user_agent' => $cliam->userAgent(),
            'ip' => $cliam->ip(), 
            'user_id' => $cliam->user(), 
            'created_at' => time()
        ];
    }
}
