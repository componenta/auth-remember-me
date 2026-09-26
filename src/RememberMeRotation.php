<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

final readonly class RememberMeRotation
{
    public function __construct(
        public RememberMeRotationState $state,
        #[\SensitiveParameter]
        public RememberMeCredential $successorCredential,
    ) {}

    /** @return array{state: string, successorCredential: string} */
    public function __debugInfo(): array
    {
        return [
            'state' => $this->state::class,
            'successorCredential' => '[REDACTED]',
        ];
    }
}
