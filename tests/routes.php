<?php

$router->group(['middleware' => ['auth']], function () use ($router) {
    
    $router->get('user', function() {
        return [
            'id' => auth()->id(),
            'sub' => auth()->getAccountId(),
            'org' => auth()->getOrganizationId()
        ];
    });


    $router->get('token', function() {
        return auth()->getAccessToken()->toArray();
    });

    $router->get('login', ['middleware' => ['gate-response'], function () {
        return auth()->getAccessToken()->toArray();
    }]);

    $router->get('logout', ['middleware' => ['gate-clear'], function () {
        return auth()->getAccessToken()->toArray();
    }]);

});


$router->post('claim', ['middleware' => ['gate-claim:sub,app-token'], function () {
    return ['sub' => app('gate')->getToken()?->sub];
}]);