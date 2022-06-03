<?php

$router->group(['middleware' => ['auth']], function () use ($router) {
    
    $router->get('user', function() {
        return [
            'id' => auth()->id(),
            'sub' => auth()->account(),
            'org' => auth()->company()
        ];
    });


    $router->get('token', function() {
        return auth()->tokenToArray();
    });

    $router->get('login', ['middleware' => ['gate-response'], function () {
        return auth()->tokenToArray();
    }]);

    $router->get('logout', ['middleware' => ['gate-clear'], function () {
        return auth()->tokenToArray();
    }]);

});