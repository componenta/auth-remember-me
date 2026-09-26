<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionCredentialPayload;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RememberMeSessionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RememberMeManagerInterface $remember,
        private AuthenticatedSessionIssuer $issuer,
        private AuthSessionManagerInterface $sessions,
        private SessionCookieTransport $sessionCookies,
        private SessionMetadataExtractorInterface $metadata,
    ) {}

    #[\Override]
    public function process(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $rotation = $request->getAttribute(RememberMeRotationState::class);

        if (!$rotation instanceof RememberMeRotationState) {
            return $handler->handle($request);
        }

        $identity = $request->getAttribute(IdentityInterface::class);
        $transportState = $request->getAttribute(
            CredentialTransportState::class,
        );

        if (
            !$identity instanceof IdentityInterface
            || !$transportState instanceof CredentialTransportState
        ) {
            $this->remember->revokeRotation($rotation);

            throw new \LogicException(
                'Remember-me session issuance requires authenticated identity and transport state.',
            );
        }

        $grant = $this->issuer->issue(
            $identity,
            RememberMeEvidence::create(),
            $this->metadata->extract($request),
        );

        $transportState->onDiscard(
            function () use ($grant): void {
                $this->sessions->revoke(
                    $grant->session->uuid,
                    RevocationReason::SecurityEvent,
                );
            },
        );

        if (!$this->remember->bindRotation($rotation, $grant->session->uuid)) {
            $this->sessions->revoke(
                $grant->session->uuid,
                RevocationReason::SecurityEvent,
            );
            $transportState->discardQueued();

            $request = $request
                ->withoutAttribute(IdentityInterface::class)
                ->withoutAttribute(AuthenticationStateInterface::class)
                ->withoutAttribute(RememberMeRotationState::class)
                ->withAttribute(
                    DeniedReasonInterface::class,
                    new InvalidCredentials(),
                );

            return $handler->handle($request);
        }

        $transportState->register($this->sessionCookies);
        $transportState->queue(
            $this->sessionCookies,
            new SessionCredentialPayload($grant->credential),
        );
        $request = $request
            ->withoutAttribute(AuthenticationStateInterface::class)
            ->withoutAttribute(RememberMeRotationState::class)
            ->withAttribute(
                AuthenticationStateInterface::class,
                $grant->session,
            )
            ->withAttribute(AuthSession::class, $grant->session);

        return $handler->handle($request);
    }
}
