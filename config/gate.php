<?php

return [

    'defaults' => [
        'key-store' => env('GATE_KEY_STORE', 'file'),
        'guard' => env('GATE_DEFAULT', 'default'),
    ],

    'issuer' => env('GATE_ISSUER', 'gate'),
    'alg' => env('GATE_ALG', 'HS256'),
    'ttl' => env('GATE_ACCESS_TOKEN_TTL', 5400),

    'key-stores' => [
        'array' => ['driver' => 'array'],
        'file' => [
            'driver' => 'file', 
            'path' => env('GATE_KEY_PATH', '/var/www/html/resources/keys')
        ],
    ],

    'guards' => [
        'default' => [
            'storage' => env('GATE_STORE', 'redis'),
            'storage-key' => 'gate-token'
        ]
    ],
    
    'cookie' => [
        'secure' => env('GATE_COOKIE_SECURE', true),
        'same' => env('GATE_COOKIE_SAME_SITE', 'none'),
    ]
];
