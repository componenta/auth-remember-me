<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Authenticator;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\RememberMe\DatabaseRememberMeManager;
use Componenta\Auth\RememberMe\RememberMeCookieTransport;
use Componenta\Auth\RememberMe\RememberMeEvidence;
use Componenta\Auth\RememberMe\RememberMeLogoutHandler;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\RememberMeSessionMiddleware;
use Componenta\Auth\RememberMe\RememberMeStrategy;
use Componenta\Auth\RememberMe\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabaseAuthSessionManager;
use Componenta\Auth\Session\Http\AuthSessionLogoutHandler;
use Componenta\Auth\Session\Http\BasicSessionMetadataExtractor;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class LogoutLifecycleTest extends TestCase
{
    public static function incomingSession(): iterable
    {
        yield 'no session cookie' => [false];
        yield 'revoked session cookie' => [true];
    }

    #[DataProvider('incomingSession')]
    public function testRememberRestorationCannotPublishAuthenticationAfterLogout(bool $includeOldCookie): void
    {
        self::requireSqlite();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $uuids = new UuidFactory();
        $identity = new class($uuids->generate()) implements IdentityInterface {
            public function __construct(public readonly UuidInterface $uuid) {}
        };
        $database = SqliteDatabaseFixture::create();
        $sourceFile = (new \ReflectionClass(DatabaseAuthSessionManager::class))->getFileName();
        self::assertIsString($sourceFile);
        $schema = file_get_contents(dirname($sourceFile, 2) . '/resources/schema/sqlite.sql');
        self::assertIsString($schema);
        foreach (array_filter(array_map('trim', explode(';', $schema))) as $sql) {
            $database->execute($sql);
        }
        $sessions = new DatabaseAuthSessionManager(
            $database, $uuids, $clock,
            new CredentialKeyring('test', ['test' => str_repeat('k', 32)]),
        );
        $remember = new DatabaseRememberMeManager($database, $clock);
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $guard->method('check')->willReturn(null);
        $policies = $this->createStub(AuthSessionPolicyProviderInterface::class);
        $policies->method('for')->willReturn(new AuthSessionPolicy(600, 3600));
        $issuer = new AuthenticatedSessionIssuer(
            $sessions, $policies, new AuthenticationAdmission($identities, $guard),
        );
        $original = $sessions->create($identity->uuid, RememberMeEvidence::create(), new AuthSessionPolicy(600, 3600));
        $remembered = $remember->create($identity->uuid, $original->session->uuid);
        $sessions->revoke($original->session->uuid, RevocationReason::Expired);
        $sessionCookies = new SessionCookieTransport();
        $rememberCookies = new RememberMeCookieTransport($clock);
        $logout = new RememberMeLogoutHandler(
            $remember, $rememberCookies,
            new AuthSessionLogoutHandler($sessionCookies, $sessions, new Psr17Factory()),
        );
        $restore = new RememberMeSessionMiddleware(
            $remember, $issuer, $sessions, $sessionCookies, new BasicSessionMetadataExtractor(),
        );
        $next = new class($restore, $logout) implements RequestHandlerInterface {
            public function __construct(
                private RememberMeSessionMiddleware $restore,
                private RequestHandlerInterface $logout,
            ) {}
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->restore->process($request, $this->logout);
            }
        };
        $authentication = new AuthenticationMiddleware(
            $rememberCookies,
            new Authenticator(new RememberMeStrategy($remember, $identities, $sessions)),
            $rememberCookies,
        );
        $cookies = [$rememberCookies->name => $remembered->credential->toString()];
        if ($includeOldCookie) {
            $cookies[$sessionCookies->name] = $original->credential->toString();
        }

        $response = $authentication->process(
            (new ServerRequest('POST', 'https://example.test/logout'))->withCookieParams($cookies),
            $next,
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame([], $sessions->all($identity->uuid));
        self::assertNull($remember->rotate($remembered->credential));
        self::assertCount(2, $response->getHeader('Set-Cookie'));
        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            self::assertStringContainsString('Max-Age=0', $cookie);
            self::assertMatchesRegularExpression('/^__Host-auth_(session|remember)=;/', $cookie);
        }
    }

    public function testOriginalBearerRevokesItsReboundSuccessorWithoutAffectingOtherGrants(): void
    {
        self::requireSqlite();
        $manager = new DatabaseRememberMeManager(
            SqliteDatabaseFixture::create(),
            new FrozenClock('2030-01-01T00:00:00Z', 'UTC'),
        );
        $uuids = new UuidFactory();
        $subject = $uuids->generate();
        $sessionA = $uuids->generate();
        $sessionB = $uuids->generate();
        $original = $manager->create($subject, $sessionA);
        $unrelated = $manager->create($subject, $sessionB);
        $rotation = $manager->rotate($original->credential);
        self::assertInstanceOf(RememberMeRotation::class, $rotation);
        self::assertTrue($manager->bindRotation($rotation->state, $sessionB));

        $manager->revokeForSession($sessionA);
        $manager->revokeCredential($original->credential);
        $manager->revokeCredential($original->credential);

        self::assertNull($manager->rotate($rotation->successorCredential));
        self::assertInstanceOf(RememberMeRotation::class, $manager->rotate($unrelated->credential));
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
