<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\RememberMe\RememberMeManagerInterface;
use Componenta\Auth\RememberMe\RememberMeRotationState;
use Componenta\Auth\RememberMe\RememberMeSessionMiddleware;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

final class AdmissionCompensationTest extends TestCase
{
    #[DataProvider('failures')]
    public function testRefusedOrFailedAdmissionRevokesUnpublishedRotation(bool $throws): void
    {
        $uuids = new UuidFactory();
        $identity = new readonly class($uuids->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $rotation = new RememberMeRotationState($identity->uuid, $uuids->generate(), str_repeat('a', 64), 2, new \DateTimeImmutable('2030-02-01T00:00:00+00:00'));
        $remember = $this->createMock(RememberMeManagerInterface::class);
        $remember->expects(self::once())->method('revokeRotation')->with($rotation);
        $remember->expects(self::never())->method('bindRotation');
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $policies = $this->createMock(AuthSessionPolicyProviderInterface::class);
        $policies->expects(self::never())->method('for');
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        if ($throws) {
            $guard->method('check')->willThrowException(new \RuntimeException('admission unavailable'));
        } else {
            $guard->method('check')->willReturn(new DeniedReason('user_disabled'));
        }
        $issuer = new AuthenticatedSessionIssuer($sessions, $policies, new AuthenticationAdmission($provider, $guard));
        $metadata = $this->createStub(SessionMetadataExtractorInterface::class);
        $metadata->method('extract')->willReturn([]);
        $middleware = new RememberMeSessionMiddleware($remember, $issuer, $sessions, new SessionCookieTransport(), $metadata);
        $request = (new ServerRequest('GET', '/'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(RememberMeRotationState::class, $rotation)
            ->withAttribute(CredentialTransportState::class, new CredentialTransportState());
        $next = $this->createMock(RequestHandlerInterface::class);
        if ($throws) {
            $next->expects(self::never())->method('handle');
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('admission unavailable');
        } else {
            $next->expects(self::once())->method('handle')->willReturnCallback(static function ($request) {
                self::assertNull($request->getAttribute(IdentityInterface::class));
                self::assertNull($request->getAttribute(RememberMeRotationState::class));
                self::assertInstanceOf(DeniedReasonInterface::class, $request->getAttribute(DeniedReasonInterface::class));
                return new Response(401);
            });
        }
        $response = $middleware->process($request, $next);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('Set-Cookie'));
    }

    public static function failures(): iterable
    {
        yield 'denied' => [false];
        yield 'infrastructure-failure' => [true];
    }
}
