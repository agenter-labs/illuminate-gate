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
        return auth()->toArray();
    });

    $router->get('login', ['middleware' => ['gate-response'], function () {
        return auth()->toArray();
    }]);

    $router->get('logout', ['middleware' => ['gate-clear'], function () {
        return auth()->toArray();
    }]);

});



$router->post('claim', ['middleware' => ['gate-claim:sub,app-token,HS256'], function () {
    return ['sub' => app('gate')->token('id')?->sub];
}]);