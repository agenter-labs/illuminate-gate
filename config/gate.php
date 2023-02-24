<?php

return [

    'provider' => 'token',

    // User identity
    'user-claim' => 'aud',

    // Access token request name in header or cookie
    'token-name' => env('GATE_ACCESS_TOKEN_NAME', 'access-token'),
    
    // Storage Key to verifiy signature 
    'storage-key' => 'gate-token',

    // ttl
    'ttl' => env('GATE_ACCESS_TOKEN_TTL', 5400),

    // Token store
    'store' => env('GATE_STORE', 'array'),

    // Token issuer
    'issuer' => env('GATE_ISSUER', 'gate'),

    // Keystore location
    'key-path' => env('GATE_KEY_PATH', ''),

    // Algorithm
    'alg' => env('GATE_ALG', 'HS256'),

    // Validate signture aginst storage
    'strict' => env('GATE_STRICT', true),

    'cookie' => [
        'secure' => env('GATE_COOKIE_SECURE', true),
        'same' => env('GATE_COOKIE_SAME_SITE', 'none'),
    ]
];
