<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

final readonly class RememberMeCompromise
{
    public function __construct(public UuidInterface $subjectId) {}
}
