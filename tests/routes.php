<?php

$router->group(['middleware' => ['auth']], function () use ($router) {
    $router->get('user', function() {
        return [
            'id' => auth()->id(),
            'sub' => auth()->account(),
            'org' => auth()->company()
        ];
    });
    $router->get('login', function() {
        return auth()->tokenToArray();
    });
});
