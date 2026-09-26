<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\RememberMe\DatabaseRememberMeManager;
use Componenta\Auth\RememberMe\RememberMeCompromise;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class DatabaseRememberMeManagerTest extends TestCase
{
    public function testRotationAndReplayReportSubjectCompromise(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = new DatabaseRememberMeManager(
            $database,
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $sessionA = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
        );
        $sessionB = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abe',
        );
        $grant = $manager->create($subject, $sessionA);
        $rotation = $manager->rotate($grant->credential);

        self::assertInstanceOf(RememberMeRotation::class, $rotation);
        self::assertTrue(
            $manager->bindRotation($rotation->state, $sessionB),
        );

        $compromise = $manager->rotate($grant->credential);

        self::assertInstanceOf(RememberMeCompromise::class, $compromise);
        self::assertTrue($compromise->subjectId->equals($subject));
        self::assertSame(
            0,
            $database->select()->from('auth_remember_me_grants')->count(),
        );
    }

    public function testDatabaseNeverStoresRawCredential(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = new DatabaseRememberMeManager(
            $database,
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $grant = $manager->create(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd'),
        );
        $row = $database->select()
            ->from('auth_remember_me_grants')
            ->run()
            ->fetch();

        self::assertIsArray($row);
        $serialized = json_encode($row, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString(
            $grant->credential->selector,
            $serialized,
        );
        self::assertStringNotContainsString(
            $grant->credential->validator,
            $serialized,
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
