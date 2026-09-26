<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class RememberMeRotationState implements
    AuthenticationStateInterface
{
    public function __construct(
        public UuidInterface $subjectId,
        public UuidInterface $previousSessionId,
        public string $selectorHash,
        public int $generation,
        public DateTimeImmutable $expiresAt,
    ) {
        if (
            preg_match('/\A[a-f0-9]{64}\z/D', $this->selectorHash) !== 1
            || $this->generation < 1
        ) {
            throw new \InvalidArgumentException(
                'Remember-me rotation state is invalid.',
            );
        }
    }
}
