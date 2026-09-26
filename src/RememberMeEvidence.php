<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\AuthenticationEvidence;

final class RememberMeEvidence
{
    private function __construct() {}

    public static function create(): AuthenticationEvidence
    {
        return new AuthenticationEvidence(
            methods: ['remember_me'],
            capabilities: ['possession', 'persistent_grant'],
        );
    }
}
