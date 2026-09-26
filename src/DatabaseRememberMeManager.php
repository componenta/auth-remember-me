<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final readonly class DatabaseRememberMeManager implements RememberMeManagerInterface
{
    private const int MAX_TTL = 31_536_000;
    private const int MAX_CLEANUP = 10_000;
    private const string DATE_FORMAT = 'Y-m-d H:i:s.u';

    public function __construct(
        private DatabaseInterface $database,
        private ClockInterface $clock,
        private string $table = 'auth_remember_me_grants',
    ) {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $this->table) !== 1) {
            throw new \InvalidArgumentException(
                'Remember-me table name is invalid.',
            );
        }
    }

    #[\Override]
    public function create(
        UuidInterface $subjectId,
        UuidInterface $sessionId,
        int $ttlSeconds = 2_592_000,
    ): RememberMeGrant {
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL) {
            throw new \InvalidArgumentException(
                'Remember-me TTL is out of bounds.',
            );
        }

        $credential = RememberMeCredential::generate();
        $now = $this->now();
        $expiresAt = $now->modify(sprintf('+%d seconds', $ttlSeconds));

        $this->database->insert($this->table)->values([
            'selector_hash' => self::selectorHash($credential),
            'verifier_hash' => self::verifierHash($credential),
            'subject_uuid' => $subjectId->toString(),
            'session_uuid' => $sessionId->toString(),
            'generation' => 1,
            'created_at' => $this->format($now),
            'expires_at' => $this->format($expiresAt),
        ])->run();

        return new RememberMeGrant(
            $subjectId,
            $sessionId,
            $credential,
            $expiresAt,
        );
    }

    #[\Override]
    public function rotate(
        #[\SensitiveParameter]
        RememberMeCredential $credential,
    ): RememberMeRotation|RememberMeCompromise|null {
        $selectorHash = self::selectorHash($credential);
        $row = $this->row($selectorHash);

        if ($row === null) {
            return null;
        }

        $now = $this->now();
        $formattedNow = $this->format($now);

        if ($this->date(self::stringValue($row, 'expires_at')) <= $now) {
            $this->database->delete($this->table)
                ->where('selector_hash', $selectorHash)
                ->where('expires_at', '<=', $formattedNow)
                ->run();

            return null;
        }

        $presentedVerifier = self::verifierHash($credential);
        $storedVerifier = self::stringValue($row, 'verifier_hash');

        if (!hash_equals($storedVerifier, $presentedVerifier)) {
            return $this->compromise($row);
        }

        $successor = $credential->successor();
        $generation = self::intValue($row, 'generation');
        $expiresAt = $this->date(self::stringValue($row, 'expires_at'));
        $affected = $this->database->update($this->table)
            ->where('selector_hash', $selectorHash)
            ->where('verifier_hash', $presentedVerifier)
            ->where('generation', $generation)
            ->where('expires_at', '>', $formattedNow)
            ->values([
                'verifier_hash' => self::verifierHash($successor),
                'generation' => $generation + 1,
                'created_at' => $formattedNow,
            ])
            ->run();

        if ($affected !== 1) {
            $current = $this->row($selectorHash);

            if ($current === null) {
                return null;
            }

            if (
                !hash_equals(
                    self::stringValue($current, 'verifier_hash'),
                    $presentedVerifier,
                )
            ) {
                return $this->compromise($current);
            }

            return null;
        }

        return new RememberMeRotation(
            new RememberMeRotationState(
                subjectId: Uuid::fromString(
                    self::stringValue($row, 'subject_uuid'),
                ),
                previousSessionId: Uuid::fromString(
                    self::stringValue($row, 'session_uuid'),
                ),
                selectorHash: $selectorHash,
                generation: $generation + 1,
                expiresAt: $expiresAt,
            ),
            $successor,
        );
    }

    #[\Override]
    public function bindRotation(
        RememberMeRotationState $rotation,
        UuidInterface $newSessionId,
    ): bool {
        $now = $this->format($this->now());
        $oldSession = $rotation->previousSessionId->toString();
        $newSession = $newSessionId->toString();
        $affected = $this->database->update($this->table)
            ->where('selector_hash', $rotation->selectorHash)
            ->where('subject_uuid', $rotation->subjectId->toString())
            ->where('session_uuid', $oldSession)
            ->where('generation', $rotation->generation)
            ->where('expires_at', '>', $now)
            ->values([
                'session_uuid' => $newSession,
            ])
            ->run();

        if ($affected === 1) {
            return true;
        }

        $row = $this->row($rotation->selectorHash);

        return $row !== null
            && self::intValue($row, 'generation') === $rotation->generation
            && self::stringValue($row, 'subject_uuid')
                === $rotation->subjectId->toString()
            && self::stringValue($row, 'session_uuid') === $newSession
            && self::stringValue($row, 'expires_at') > $now;
    }

    #[\Override]
    public function revokeRotation(RememberMeRotationState $rotation): void
    {
        $this->database->delete($this->table)
            ->where('selector_hash', $rotation->selectorHash)
            ->where('generation', $rotation->generation)
            ->run();
    }

    #[\Override]
    public function revokeCredential(
        #[\SensitiveParameter]
        RememberMeCredential $credential,
    ): void {
        $this->database->delete($this->table)
            ->where('selector_hash', self::selectorHash($credential))
            ->where('verifier_hash', self::verifierHash($credential))
            ->run();
    }

    #[\Override]
    public function revokeForSession(UuidInterface $sessionId): void
    {
        $this->database->delete($this->table)
            ->where('session_uuid', $sessionId->toString())
            ->run();
    }

    #[\Override]
    public function revokeAllForSubject(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
    ): void {
        $query = $this->database->delete($this->table)
            ->where('subject_uuid', $subjectId->toString());

        if ($exceptSessionId !== null) {
            $query->where('session_uuid', '!=', $exceptSessionId->toString());
        }

        $query->run();
    }

    #[\Override]
    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > self::MAX_CLEANUP) {
            throw new \InvalidArgumentException(
                'Remember-me cleanup limit is out of bounds.',
            );
        }

        $now = $this->format($this->now());
        $rows = $this->database->select('selector_hash')
            ->from($this->table)
            ->where('expires_at', '<=', $now)
            ->limit($limit)
            ->run()
            ->fetchAll();
        $hashes = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['selector_hash'] ?? null)) {
                $hashes[] = $row['selector_hash'];
            }
        }

        return $hashes === []
            ? 0
            : $this->database->delete($this->table)
                ->where('selector_hash', 'IN', $hashes)
                ->run();
    }

    /** @param array<array-key, mixed> $row */
    private function compromise(array $row): RememberMeCompromise
    {
        $selectorHash = self::stringValue($row, 'selector_hash');
        $this->database->delete($this->table)
            ->where('selector_hash', $selectorHash)
            ->run();

        return new RememberMeCompromise(
            Uuid::fromString(self::stringValue($row, 'subject_uuid')),
        );
    }

    /** @return array<array-key, mixed>|null */
    private function row(string $selectorHash): ?array
    {
        $row = $this->database->select()
            ->from($this->table)
            ->where('selector_hash', $selectorHash)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    private static function selectorHash(
        #[\SensitiveParameter]
        RememberMeCredential $credential,
    ): string {
        return hash(
            'sha256',
            "componenta-auth-remember-selector-v1\0" . $credential->selector(),
        );
    }

    private static function verifierHash(
        #[\SensitiveParameter]
        RememberMeCredential $credential,
    ): string {
        return hash(
            'sha256',
            "componenta-auth-remember-validator-v1\0"
                . $credential->selector()
                . "\0"
                . $credential->validator(),
        );
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $date): string
    {
        return $date->setTimezone(new DateTimeZone('UTC'))
            ->format(self::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        $timezone = new DateTimeZone('UTC');

        foreach (['!Y-m-d H:i:s.u', '!Y-m-d H:i:s'] as $format) {
            $date = DateTimeImmutable::createFromFormat(
                $format,
                $value,
                $timezone,
            );

            if ($date instanceof DateTimeImmutable) {
                return $date;
            }
        }

        throw new \UnexpectedValueException(
            'Persisted remember-me timestamp is invalid.',
        );
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" is invalid.', $key),
            );
        }

        return (string) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(array $row, string $key): int
    {
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" must be an integer.', $key),
            );
        }

        return (int) $value;
    }
}
