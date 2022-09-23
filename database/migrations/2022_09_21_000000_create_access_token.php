<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Config;

class CreateAccessToken extends Migration
{

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function up()
    {
		Schema::create(Config::get('gate.repository.table'), function (Blueprint $table) {
            $table->unsignedBigInteger('id')->primary();
            $table->unsignedBigInteger('user_id')->default(0)->index();
            $table->string('user_agent', 500);
            $table->string('ip', 40);
            $table->unsignedBigInteger('created_at');
        });
    }

    /**
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists(Config::get('gate.repository.table'));
    }
}