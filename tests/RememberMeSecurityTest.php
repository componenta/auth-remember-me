<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Context;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\RememberMe\RememberMeCompromise;
use Componenta\Auth\RememberMe\RememberMeCredential;
use Componenta\Auth\RememberMe\RememberMeManagerInterface;
use Componenta\Auth\RememberMe\RememberMePresentedCredential;
use Componenta\Auth\RememberMe\RememberMeRotationState;
use Componenta\Auth\RememberMe\RememberMeSessionMiddleware;
use Componenta\Auth\RememberMe\RememberMeStrategy;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RememberMeSecurityTest extends TestCase
{
    public function testReplayCompromiseRevokesEveryActiveSessionForSubject(): void
    {
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $remember = $this->createStub(RememberMeManagerInterface::class);
        $remember->method('rotate')->willReturn(
            new RememberMeCompromise($subject),
        );
        $identities = $this->createMock(IdentityProviderInterface::class);
        $identities->expects(self::never())->method('findByUuid');
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::once())
            ->method('revokeAll')
            ->with(
                self::callback(
                    static fn(UuidInterface $id): bool =>
                        $id->equals($subject),
                ),
            );

        $result = (new RememberMeStrategy(
            $remember,
            $identities,
            $sessions,
        ))->attempt(
            new RememberMePresentedCredential(
                RememberMeCredential::generate(),
            ),
            new Context(),
        );

        self::assertInstanceOf(
            \Componenta\Auth\Denied\InvalidCredentials::class,
            $result->subject,
        );
    }

    public function testIssuedSessionHasDiscardCompensationBeforeBinding(): void
    {
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $sessionId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abe',
        );
        $identity = new RememberMeIdentityFixture($subject);
        $evidence = new AuthenticationEvidence(
            ['remember_me'],
            ['possession', 'persistent_grant'],
        );
        $grant = self::grant($subject, $sessionId, $evidence);
        $sessions = new RememberMeSessionManagerFixture($grant);
        $remember = new ThrowingBindRememberMeManagerFixture();
        $issuer = new AuthenticatedSessionIssuer(
            $sessions,
            new FixedRememberMePolicyProviderFixture(
                new AuthSessionPolicy(1800, 28800),
            ),
        );
        $transportState = new CredentialTransportState();
        $rotation = new RememberMeRotationState(
            subjectId: $subject,
            previousSessionId: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
            ),
            selectorHash: str_repeat('a', 64),
            generation: 2,
            expiresAt: new DateTimeImmutable(
                '2030-01-31T00:00:00+00:00',
            ),
        );
        $request = (new ServerRequest('GET', '/'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(CredentialTransportState::class, $transportState)
            ->withAttribute(RememberMeRotationState::class, $rotation);
        $middleware = new RememberMeSessionMiddleware(
            $remember,
            $issuer,
            $sessions,
            new SessionCookieTransport(),
            new EmptyMetadataExtractorFixture(),
        );

        try {
            $middleware->process($request, new NeverHandlerFixture());
            self::fail('Binding failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('bind failed', $exception->getMessage());
        }

        self::assertSame([], $sessions->revoked);

        $transportState->discardQueued();

        self::assertCount(1, $sessions->revoked);
        self::assertTrue($sessions->revoked[0]->equals($sessionId));
    }

    private static function grant(
        UuidInterface $subjectId,
        UuidInterface $sessionId,
        AuthenticationEvidence $evidence,
    ): AuthSessionGrant {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSessionGrant(
            new AuthSession(
                uuid: $sessionId,
                subjectId: $subjectId,
                evidence: $evidence,
                credentialGeneration: 1,
                createdAt: $now,
                authenticatedAt: $now,
                reauthenticatedAt: null,
                lastActiveAt: $now,
                idleExpiresAt: $now->modify('+30 minutes'),
                absoluteExpiresAt: $now->modify('+8 hours'),
            ),
            SessionCredential::fromBytes(str_repeat('s', 32)),
        );
    }
}

final readonly class RememberMeIdentityFixture implements IdentityInterface
{
    public function __construct(public UuidInterface $uuid) {}
}

final class RememberMeSessionManagerFixture implements
    AuthSessionManagerInterface
{
    /** @var list<UuidInterface> */
    public array $revoked = [];

    public function __construct(private AuthSessionGrant $grant) {}

    public function create(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
        AuthSessionPolicy $policy,
        array $metadata = [],
    ): AuthSessionGrant {
        return $this->grant;
    }

    public function resume(SessionCredential $credential): ?AuthSession
    {
        return null;
    }

    public function touch(AuthSession $observed): void {}

    public function rotate(
        AuthSession $observed,
        AuthenticationEvidence $evidence,
        RotationReason $reason,
        ?AuthSessionPolicy $policy = null,
    ): AuthSessionGrant {
        return $this->grant;
    }

    public function revoke(
        UuidInterface $sessionId,
        RevocationReason $reason,
    ): void {
        $this->revoked[] = $sessionId;
    }

    public function revokePresentedCredential(
        SessionCredential $credential,
        RevocationReason $reason,
    ): void {}

    public function revokeAll(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
    ): void {}

    public function isGrantCurrent(AuthSessionGrant $grant): bool
    {
        return true;
    }
}

final readonly class FixedRememberMePolicyProviderFixture implements
    AuthSessionPolicyProviderInterface
{
    public function __construct(private AuthSessionPolicy $policy) {}

    public function for(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): AuthSessionPolicy {
        return $this->policy;
    }
}

final class ThrowingBindRememberMeManagerFixture implements
    RememberMeManagerInterface
{
    public function create(
        UuidInterface $subjectId,
        UuidInterface $sessionId,
        int $ttlSeconds = 2592000,
    ): \Componenta\Auth\RememberMe\RememberMeGrant {
        throw new \LogicException('Not used.');
    }

    public function rotate(
        RememberMeCredential $credential,
    ): \Componenta\Auth\RememberMe\RememberMeRotation|
        RememberMeCompromise|null {
        return null;
    }

    public function bindRotation(
        RememberMeRotationState $rotation,
        UuidInterface $newSessionId,
    ): bool {
        throw new \RuntimeException('bind failed');
    }

    public function revokeRotation(RememberMeRotationState $rotation): void {}

    public function revokeCredential(RememberMeCredential $credential): void {}

    public function revokeForSession(UuidInterface $sessionId): void {}

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
    ): void {}

    public function cleanup(int $limit = 1000): int
    {
        return 0;
    }
}

final readonly class EmptyMetadataExtractorFixture implements
    SessionMetadataExtractorInterface
{
    public function extract(ServerRequestInterface $request): array
    {
        return [];
    }
}

final class NeverHandlerFixture implements RequestHandlerInterface
{
    public function handle(
        ServerRequestInterface $request,
    ): ResponseInterface {
        throw new \LogicException('Downstream handler must not run.');
    }
}
