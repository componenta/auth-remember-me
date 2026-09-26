<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Http\CredentialResponseHeaders;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class RememberMeGrantPublisher
{
    public function __construct(
        private RememberMeManagerInterface $remember,
        private RememberMeCookieTransport $transport,
    ) {}

    public function publish(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        RememberMeGrant $grant,
    ): ResponseInterface {
        try {
            return CredentialResponseHeaders::apply(
                $this->transport->store(
                    $request,
                    $response,
                    new RememberMeCookieGrant(
                        $grant->credential,
                        $grant->expiresAt,
                    ),
                ),
            );
        } catch (\Throwable $exception) {
            $this->remember->revokeCredential($grant->credential);
            throw $exception;
        }
    }
}
