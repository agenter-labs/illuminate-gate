<?php

return [

    'provider' => 'token',

    'user-claim' => 'aud',

    // Access token request name in header or cookie
    'access_token_name' => env('GATE_ACCESS_TOKEN_NAME', 'api-token'),

    // ID token request name in header, body or cookie
    'id_token_name' => env('GATE_ID_TOKEN_NAME', 'app-token'),

    // ID key
    'id_provider_key' => env('GATE_ID_PROVIDER_KEY', ''),

    // Gate token encryption key
    'secrete_key' => env('GATE_SECRETE_KEY', ''),

    // ttl
    'ttl' => env('GATE_ACCESS_TOKEN_TTL', 5400),

    // Token store
    'store' => env('GATE_STORE', 'array'),

    // Token store
    'strict' => env('GATE_STRICT', true),

    'cookie' => [
        'secure' => env('GATE_COOKIE_SECURE', true),
        'same_site' => env('GATE_COOKIE_SAME_SITE', 'none'),
    ]
];
