<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class RememberMeGrant
{
    public function __construct(
        public UuidInterface $subjectId,
        public UuidInterface $sessionId,
        #[\SensitiveParameter]
        public RememberMeCredential $credential,
        public DateTimeImmutable $expiresAt,
    ) {}

    /** @return array{subjectId: string, sessionId: string, credential: string, expiresAt: string} */
    public function __debugInfo(): array
    {
        return [
            'subjectId' => $this->subjectId->toString(),
            'sessionId' => $this->sessionId->toString(),
            'credential' => '[REDACTED]',
            'expiresAt' => $this->expiresAt->format(DATE_ATOM),
        ];
    }
}
