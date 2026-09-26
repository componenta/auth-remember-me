<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

interface RememberMeManagerInterface
{
    public function create(
        UuidInterface $subjectId,
        UuidInterface $sessionId,
        int $ttlSeconds = 2_592_000,
    ): RememberMeGrant;

    public function rotate(
        #[\SensitiveParameter]
        RememberMeCredential $credential,
    ): RememberMeRotation|RememberMeCompromise|null;

    public function bindRotation(
        RememberMeRotationState $rotation,
        UuidInterface $newSessionId,
    ): bool;

    public function revokeRotation(RememberMeRotationState $rotation): void;

    public function revokeCredential(
        #[\SensitiveParameter]
        RememberMeCredential $credential,
    ): void;

    public function revokeForSession(UuidInterface $sessionId): void;

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
    ): void;

    public function cleanup(int $limit = 1000): int;
}
