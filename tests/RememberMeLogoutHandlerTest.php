<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\RememberMe\RememberMeCookieTransport;
use Componenta\Auth\RememberMe\RememberMeCredential;
use Componenta\Auth\RememberMe\RememberMeGrant;
use Componenta\Auth\RememberMe\RememberMeLogoutHandler;
use Componenta\Auth\RememberMe\RememberMeManagerInterface;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\RememberMeCompromise;
use Componenta\Auth\RememberMe\RememberMeRotationState;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RememberMeLogoutHandlerTest extends TestCase
{
    public function testLogoutRevokesLinkedGrantAndPresentedCredentialAndClearsCookie(): void
    {
        $session = self::session();
        $credential = RememberMeCredential::generate();
        $manager = new LogoutRememberMeManagerFixture();
        $transport = new RememberMeCookieTransport(
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $request = (new ServerRequest('POST', '/logout'))
            ->withAttribute(AuthSession::class, $session)
            ->withCookieParams([
                '__Host-auth_remember' => $credential->toString(),
            ]);
        $sessionLogout = new LogoutSessionHandlerFixture();

        $response = (new RememberMeLogoutHandler(
            $manager,
            $transport,
            $sessionLogout,
        ))->handle($request);

        self::assertCount(1, $manager->revokedSessions);
        self::assertTrue(
            $manager->revokedSessions[0]->equals($session->uuid),
        );
        self::assertCount(1, $manager->revokedCredentials);
        self::assertSame(
            $credential->toString(),
            $manager->revokedCredentials[0]->toString(),
        );
        self::assertSame(1, $sessionLogout->calls);

        $cookie = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString(
            '__Host-auth_remember=',
            $cookie,
        );
        self::assertStringContainsString('Max-Age=0', $cookie);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    private static function session(): AuthSession
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSession(
            uuid: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            subjectId: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
            ),
            evidence: new AuthenticationEvidence(['password']),
            credentialGeneration: 1,
            createdAt: $now,
            authenticatedAt: $now,
            reauthenticatedAt: null,
            lastActiveAt: $now,
            idleExpiresAt: $now->modify('+30 minutes'),
            absoluteExpiresAt: $now->modify('+8 hours'),
        );
    }
}

final class LogoutRememberMeManagerFixture implements
    RememberMeManagerInterface
{
    /** @var list<UuidInterface> */
    public array $revokedSessions = [];

    /** @var list<RememberMeCredential> */
    public array $revokedCredentials = [];

    public function create(
        UuidInterface $subjectId,
        UuidInterface $sessionId,
        int $ttlSeconds = 2592000,
    ): RememberMeGrant {
        throw new \LogicException('Not used.');
    }

    public function rotate(
        RememberMeCredential $credential,
    ): RememberMeRotation|RememberMeCompromise|null {
        return null;
    }

    public function bindRotation(
        RememberMeRotationState $rotation,
        UuidInterface $newSessionId,
    ): bool {
        return false;
    }

    public function revokeRotation(RememberMeRotationState $rotation): void {}

    public function revokeCredential(RememberMeCredential $credential): void
    {
        $this->revokedCredentials[] = $credential;
    }

    public function revokeForSession(UuidInterface $sessionId): void
    {
        $this->revokedSessions[] = $sessionId;
    }

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
    ): void {}

    public function cleanup(int $limit = 1000): int
    {
        return 0;
    }
}

final class LogoutSessionHandlerFixture implements RequestHandlerInterface
{
    public int $calls = 0;

    public function handle(
        ServerRequestInterface $request,
    ): ResponseInterface {
        ++$this->calls;

        return new Response(204);
    }
}
