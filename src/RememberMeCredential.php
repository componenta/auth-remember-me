<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

final readonly class RememberMeCredential implements \Stringable
{
    private const int SELECTOR_BYTES = 16;
    private const int VALIDATOR_BYTES = 32;

    private function __construct(
        #[\SensitiveParameter]
        public string $selector,
        #[\SensitiveParameter]
        public string $validator,
    ) {
        if (
            preg_match('/\A[A-Za-z0-9_-]{22}\z/D', $this->selector) !== 1
            || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->validator) !== 1
        ) {
            throw new \InvalidArgumentException(
                'Remember-me credential is invalid.',
            );
        }
    }

    public static function generate(): self
    {
        return new self(
            self::encode(random_bytes(self::SELECTOR_BYTES)),
            self::encode(random_bytes(self::VALIDATOR_BYTES)),
        );
    }

    public static function fromString(
        #[\SensitiveParameter]
        string $value,
    ): self {
        $parts = explode('.', $value, 2);

        if (count($parts) !== 2) {
            throw new \InvalidArgumentException(
                'Remember-me credential is invalid.',
            );
        }

        return new self($parts[0], $parts[1]);
    }

    public function successor(): self
    {
        return new self(
            $this->selector,
            self::encode(random_bytes(self::VALIDATOR_BYTES)),
        );
    }

    #[\Override]
    public function __toString(): string
    {
        return $this->toString();
    }

    public function toString(): string
    {
        return $this->selector . '.' . $this->validator;
    }

    /** @return array{credential: string} */
    public function __debugInfo(): array
    {
        return ['credential' => '[REDACTED]'];
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
