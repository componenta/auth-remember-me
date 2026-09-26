<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use DateTimeImmutable;

final readonly class RememberMeCookieGrant
{
    public function __construct(
        #[\SensitiveParameter]
        public RememberMeCredential $credential,
        public DateTimeImmutable $expiresAt,
    ) {}
}
