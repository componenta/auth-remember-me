<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\RememberMe\DatabaseRememberMeManager;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class PrimaryReadConsistencyTest extends TestCase
{
    public function testNewGrantCanRotateBeforeReplication(): void
    {
        [$writer, , $reader] = $this->fixture();
        $uuids = new UuidFactory();
        $grant = $writer->create($uuids->generate(), $uuids->generate());
        self::assertInstanceOf(RememberMeRotation::class, $reader->rotate($grant->credential));
    }

    public function testCurrentSuccessorIsNotReportedAsCompromiseByLaggingReplica(): void
    {
        [$writer, $primary, $reader, $replica] = $this->fixture();
        $uuids = new UuidFactory();
        $grant = $writer->create($uuids->generate(), $uuids->generate());
        foreach ($primary->select()->from('auth_remember_me_grants')->run()->fetchAll() as $row) {
            $replica->insert('auth_remember_me_grants')->values($row)->run();
        }
        $first = $writer->rotate($grant->credential);
        self::assertInstanceOf(RememberMeRotation::class, $first);
        $second = $reader->rotate($first->successorCredential);
        self::assertInstanceOf(RememberMeRotation::class, $second);
        self::assertSame(1, $primary->select()->from('auth_remember_me_grants')->count());
    }

    public function testRevokedGrantStaysRevokedEvenIfReplicaStillHasIt(): void
    {
        [$writer, $primary, $reader, $replica] = $this->fixture();
        $uuids = new UuidFactory();
        $grant = $writer->create($uuids->generate(), $uuids->generate());
        foreach ($primary->select()->from('auth_remember_me_grants')->run()->fetchAll() as $row) {
            $replica->insert('auth_remember_me_grants')->values($row)->run();
        }
        $writer->revokeCredential($grant->credential);
        self::assertNull($reader->rotate($grant->credential));
    }

    /** @return array{DatabaseRememberMeManager, DatabaseInterface, DatabaseRememberMeManager, DatabaseInterface} */
    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $primary = SqliteDatabaseFixture::create();
        $replica = SqliteDatabaseFixture::create();
        $split = new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ));
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        return [new DatabaseRememberMeManager($primary, $clock), $primary, new DatabaseRememberMeManager($split, $clock), $replica];
    }
}
