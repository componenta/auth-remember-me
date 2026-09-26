<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\RememberMe\RememberMeCredential;
use PHPUnit\Framework\TestCase;

final class RememberMeCredentialTest extends TestCase
{
    public function testSuccessorKeepsSelectorAndRotatesValidator(): void
    {
        $credential = RememberMeCredential::generate();
        $successor = $credential->successor();

        self::assertSame($credential->selector(), $successor->selector());
        self::assertNotSame($credential->validator(), $successor->validator());
        self::assertStringNotContainsString(
            $credential->toString(),
            json_encode($credential->__debugInfo(), JSON_THROW_ON_ERROR),
        );
        self::assertStringNotContainsString(
            $credential->toString(),
            json_encode($credential, JSON_THROW_ON_ERROR),
        );
        self::assertNotInstanceOf(\Stringable::class, $credential);
    }
}
