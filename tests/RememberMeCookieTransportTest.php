<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\RememberMe\RememberMeCookieGrant;
use Componenta\Auth\RememberMe\RememberMeCookieTransport;
use Componenta\Auth\RememberMe\RememberMeCredential;
use Componenta\Clock\FrozenClock;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RememberMeCookieTransportTest extends TestCase
{
    public function testPersistentCookieUsesHostSecurityAttributes(): void
    {
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $transport = new RememberMeCookieTransport($clock);
        $response = $transport->store(
            new ServerRequest('GET', '/'),
            new Response(),
            new RememberMeCookieGrant(
                RememberMeCredential::generate(),
                new DateTimeImmutable('2030-01-31T00:00:00+00:00'),
            ),
        );
        $cookie = $response->getHeaderLine('Set-Cookie');

        self::assertStringContainsString('__Host-auth_remember=', $cookie);
        self::assertStringContainsString('Path=/', $cookie);
        self::assertStringContainsString('Secure', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertStringContainsString('Max-Age=2592000', $cookie);
        self::assertStringNotContainsString('Domain=', $cookie);
    }
}
