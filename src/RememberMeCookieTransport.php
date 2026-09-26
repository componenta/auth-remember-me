<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Exception\TransportException;
use Componenta\Auth\Http\TransportInterface;
use DateTimeZone;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class RememberMeCookieTransport implements TransportInterface
{
    public string $sameSite;

    public function __construct(
        private ClockInterface $clock,
        public string $name = '__Host-auth_remember',
        string $sameSite = 'Lax',
    ) {
        if (
            !str_starts_with($this->name, '__Host-')
            || preg_match('/\A[!#$%&\'*+.^_\x60|~0-9A-Za-z-]+\z/D', $this->name) !== 1
        ) {
            throw new \InvalidArgumentException(
                'Remember-me cookie must use a valid __Host- name.',
            );
        }

        $this->sameSite = match (strtolower($sameSite)) {
            'lax' => 'Lax',
            'strict' => 'Strict',
            'none' => 'None',
            default => throw new \InvalidArgumentException(
                'SameSite must be Lax, Strict or None.',
            ),
        };
    }

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?object {
        $cookies = $request->getCookieParams();

        if (!array_key_exists($this->name, $cookies)) {
            return null;
        }

        $value = $cookies[$this->name];

        if (!is_string($value) || $value === '') {
            throw InvalidPayloadException::invalidField($this->name);
        }

        try {
            return new RememberMePresentedCredential(
                RememberMeCredential::fromString($value),
            );
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField($this->name);
        }
    }

    #[\Override]
    public function store(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        object $payload,
    ): ResponseInterface {
        if (!$payload instanceof RememberMeCookieGrant) {
            throw new TransportException(
                'Remember-me cookie transport received an unsupported payload.',
            );
        }

        $now = $this->clock->now();
        $maxAge = $payload->expiresAt->getTimestamp() - $now->getTimestamp();

        if ($maxAge <= 0) {
            return $this->remove($request, $response);
        }

        $expires = $payload->expiresAt
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('D, d M Y H:i:s \G\M\T');

        return $this->replaceCookie(
            $response,
            $this->cookie(
                $payload->credential->toString(),
                $expires,
                $maxAge,
            ),
        );
    }

    #[\Override]
    public function remove(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return $this->replaceCookie(
            $response,
            $this->cookie('', 'Thu, 01 Jan 1970 00:00:00 GMT', 0),
        );
    }

    private function cookie(
        #[\SensitiveParameter]
        string $value,
        string $expires,
        int $maxAge,
    ): string {
        return implode('; ', [
            sprintf('%s=%s', $this->name, rawurlencode($value)),
            'Path=/',
            'Expires=' . $expires,
            'Max-Age=' . $maxAge,
            'SameSite=' . $this->sameSite,
            'Secure',
            'HttpOnly',
        ]);
    }

    private function replaceCookie(
        ResponseInterface $response,
        #[\SensitiveParameter]
        string $cookie,
    ): ResponseInterface {
        $existing = array_filter(
            $response->getHeader('Set-Cookie'),
            fn(string $header): bool => !str_starts_with(
                $header,
                $this->name . '=',
            ),
        );
        $response = $response->withoutHeader('Set-Cookie');

        foreach ($existing as $header) {
            $response = $response->withAddedHeader('Set-Cookie', $header);
        }

        return $response->withAddedHeader('Set-Cookie', $cookie);
    }
}
