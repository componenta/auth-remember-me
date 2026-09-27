<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Http\CredentialResponseHeaders;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Session\AuthSession;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Logout wrapper for applications that enable remember-me.
 *
 * Persistent grants are revoked before the active-session logout handler runs.
 * This fails closed: if active-session logout later fails, the remembered
 * credential can no longer restore authentication.
 */
final readonly class RememberMeLogoutHandler implements RequestHandlerInterface
{
    public function __construct(
        private RememberMeManagerInterface $remember,
        private RememberMeCookieTransport $transport,
        private RequestHandlerInterface $sessionLogout,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $state = $request->getAttribute(CredentialTransportState::class);
        if ($state instanceof CredentialTransportState) {
            $state->clear($this->transport);
        }

        $session = $request->getAttribute(AuthSession::class);
        $payload = $this->transport->extract($request);

        if ($session instanceof AuthSession) {
            $this->remember->revokeForSession($session->uuid);
        }

        if ($payload instanceof RememberMePresentedCredential) {
            $this->remember->revokeCredential($payload->credential);
        }

        $response = $this->sessionLogout->handle($request);

        return CredentialResponseHeaders::apply(
            $this->transport->remove($request, $response),
        );
    }
}
