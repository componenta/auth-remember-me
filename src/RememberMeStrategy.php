<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\RevocationReason;

final readonly class RememberMeStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private RememberMeManagerInterface $remember,
        private IdentityProviderInterface $identities,
        private AuthSessionManagerInterface $sessions,
    ) {}

    #[\Override]
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof RememberMePresentedCredential;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        if (!$payload instanceof RememberMePresentedCredential) {
            return $this->softDenied();
        }

        $rotation = $this->remember->rotate($payload->credential);

        if ($rotation instanceof RememberMeCompromise) {
            $this->sessions->revokeAll(
                $rotation->subjectId,
                reason: RevocationReason::CredentialCompromise,
            );

            return new AuthenticationResult(new InvalidCredentials());
        }

        if (!$rotation instanceof RememberMeRotation) {
            return $this->softDenied();
        }

        try {
            $identity = $this->identities->findByUuid(
                $rotation->state->subjectId,
            );
        } catch (\Throwable $exception) {
            $this->remember->revokeRotation($rotation->state);
            throw $exception;
        }

        if (
            $identity === null
            || !$identity->uuid->equals($rotation->state->subjectId)
        ) {
            $this->remember->revokeRotation($rotation->state);

            return $this->softDenied();
        }

        $transportState = $context->getAttribute(
            CredentialTransportState::class,
        );

        if (!$transportState instanceof CredentialTransportState) {
            $this->remember->revokeRotation($rotation->state);

            throw new \LogicException(
                'Remember-me rotation requires CredentialTransportState.',
            );
        }

        $transportState->onDiscard(
            function () use ($rotation): void {
                $this->remember->revokeRotation($rotation->state);
            },
        );

        return new AuthenticationResult(
            subject: $identity,
            transportPayload: new RememberMeCookieGrant(
                $rotation->successorCredential,
                $rotation->state->expiresAt,
            ),
            state: $rotation->state,
            evidence: RememberMeEvidence::create(),
        );
    }

    private function softDenied(): AuthenticationResult
    {
        return new AuthenticationResult(
            new InvalidCredentials(),
            continueOnFailure: true,
        );
    }
}
