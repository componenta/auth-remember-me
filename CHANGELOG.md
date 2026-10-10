# Changelog

## v2.0.0 (2026-10-10)

### Dependency compatibility
- Require `componenta/auth-session-http ^2.0.1` instead of ^1.0.
- Adopt its `componenta/http-csrf-middleware ^3.0` browser security dependency transitively.
- Preserve the existing persistent credential and resumption public API; no second session issuer or CSRF implementation is introduced.
- Update the development branch alias to `2.0.x-dev`.

### Migration
- Consumers must upgrade `componenta/auth-session-http` to 2.0.1 or newer within major 2 and use the CSRF v3 family.
- Browser clients must provide permitted Origin/Referer information for unsafe CSRF-protected operations; do not bypass fail-closed verification.
- Upgrade in a coordinated dependency graph; `componenta/auth-session-http` 1.x cannot coexist with this release.
- Validate actual HTTP / session / CSRF interaction on PHP 8.4 and 8.5 before deploying the new stack.

### Verification
- The GitHub release workflow checks Composer metadata, dependency resolution, dependency advisories, PHPStan and PHPUnit on both supported PHP versions before publishing its tag.
