<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Authentication Guards
    |--------------------------------------------------------------------------
    |
    | Next, you may define every authentication guard for your application.
    | Of course, a great default configuration has been defined for you
    | here which uses session storage and the Eloquent user provider.
    |
    | All authentication drivers have a user provider. This defines how the
    | users are actually retrieved out of your database or other storage
    | mechanisms used by this application to persist your user's data.
    |
    | Supported: "token"
    |
    */

    'guards' => [
        'api' => [
            'driver' => 'token',
            'provider' => 'users',
            'hash' => false,
        ],
    ],

    'input_key' => env('GATE_TOKEN_NAME', 'api-token'),
    'app_token_name' => env('GATE_APP_TOKEN_NAME', 'app-token'),
    'app_private_key' => env('GATE_SECRETE_KEY', ''),
];
