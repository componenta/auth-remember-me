<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

final readonly class RememberMePresentedCredential
{
    public function __construct(
        #[\SensitiveParameter]
        public RememberMeCredential $credential,
    ) {}
}
