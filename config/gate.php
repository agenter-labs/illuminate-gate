<?php

return [

    'provider' => 'token',

    'user-claim' => 'aud',

    // Access token request name in header or cookie
    'access-token-name' => env('GATE_ACCESS_TOKEN_NAME', 'access-token'),
    
    'storage-key' => 'api_token',

    // ttl
    'ttl' => env('GATE_ACCESS_TOKEN_TTL', 5400),

    // Token store
    'store' => env('GATE_STORE', 'array'),

    // Token issuer
    'issuer' => env('GATE_ISSUER', 'gate'),

    'key-path' => env('GATE_KEY_PATH', ''),

    'algo' => env('GATE_ALGO', 'HS256'),

    // Token store
    'strict' => env('GATE_STRICT', true),

    'cookie' => [
        'secure' => env('GATE_COOKIE_SECURE', true),
        'same' => env('GATE_COOKIE_SAME_SITE', 'none'),
    ]
];
