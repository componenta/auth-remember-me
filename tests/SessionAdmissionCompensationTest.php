<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\RememberMe\RememberMeManagerInterface;
use Componenta\Auth\RememberMe\RememberMeRotationState;
use Componenta\Auth\RememberMe\RememberMeSessionMiddleware;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SessionAdmissionCompensationTest extends TestCase
{
    public static function failures(): iterable
    {
        yield 'denial' => [false, false];
        yield 'store exception' => [true, false];
        yield 'revocation exception' => [false, true];
    }

    #[DataProvider('failures')]
    public function testUnpublishedRememberMeSuccessorIsDiscardedWhenFinalAdmissionFails(bool $throws, bool $revocationThrows): void
    {
        $uuids = new UuidFactory();
        $identity = new class($uuids->generate()) implements IdentityInterface {
            public function __construct(public readonly UuidInterface $uuid) {}
        };
        $rotation = new RememberMeRotationState($identity->uuid, $uuids->generate(), str_repeat('a', 64), 2, new \DateTimeImmutable('2030-01-31T00:00:00Z'));
        $guard = $this->createMock(AuthenticationGuardInterface::class);
        $check = $guard->expects(self::once())->method('check');
        if ($throws) {
            $check->willThrowException(new \RuntimeException('Admission store unavailable.'));
        } else {
            $check->willReturn(new InvalidCredentials());
        }
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $policies = $this->createMock(AuthSessionPolicyProviderInterface::class);
        $policies->expects(self::never())->method('for');
        $remember = $this->createMock(RememberMeManagerInterface::class);
        $revoke = $remember->expects(self::once())->method('revokeRotation')->with($rotation);
        if ($revocationThrows) {
            $revoke->willThrowException(new \RuntimeException('Revocation store unavailable.'));
        }
        $remember->expects(self::never())->method('bindRotation');
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $discarded = false;
        $state->onDiscard(static function () use (&$discarded): void { $discarded = true; });
        $metadata = $this->createStub(SessionMetadataExtractorInterface::class);
        $metadata->method('extract')->willReturn([]);
        $request = (new ServerRequest('GET', 'https://example.com/'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(AuthenticationStateInterface::class, $rotation)
            ->withAttribute(RememberMeRotationState::class, $rotation)
            ->withAttribute(CredentialTransportState::class, $state);
        $next = $this->createMock(RequestHandlerInterface::class);
        $next->expects($throws || $revocationThrows ? self::never() : self::once())->method('handle')
            ->with(self::callback(static fn (ServerRequestInterface $request): bool =>
                $request->getAttribute(IdentityInterface::class) === null
                && $request->getAttribute(AuthenticationStateInterface::class) === null
                && $request->getAttribute(RememberMeRotationState::class) === null
                && $request->getAttribute(AuthSession::class) === null
                && $request->getAttribute(DeniedReasonInterface::class) instanceof InvalidCredentials
            ))->willReturn(new Response(401));
        $identities = $this->createStub(\Componenta\Auth\IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $middleware = new RememberMeSessionMiddleware($remember, new AuthenticatedSessionIssuer($sessions, $policies, new \Componenta\Auth\AuthenticationAdmission($identities, $guard)), $sessions, new SessionCookieTransport(), $metadata);
        try {
            $response = $middleware->process($request, $next);
            self::assertFalse($throws || $revocationThrows, 'An infrastructure error must propagate.');
            self::assertSame(401, $response->getStatusCode());
        } catch (\RuntimeException $exception) {
            self::assertTrue($throws || $revocationThrows);
            self::assertSame($revocationThrows ? 'Revocation store unavailable.' : 'Admission store unavailable.', $exception->getMessage());
        }
        self::assertTrue($discarded);
        self::assertTrue($state->empty);
        self::assertSame('', $state->apply($request, new Response())->getHeaderLine('Set-Cookie'));
    }
}
