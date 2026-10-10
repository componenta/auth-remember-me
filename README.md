# Componenta Auth Remember Me

Rotating persistent convenience grants for Componenta Auth 3.

Remember-me is deliberately separate from the active authentication session.
A valid remember grant proves possession of a persistent browser credential,
then creates a fresh non-persistent `AuthSession`.

Security properties:

- selector + validator credentials with rotating validators;
- only selector/verifier hashes are persisted;
- replay of a superseded validator is treated as compromise;
- compromise revokes the remembered grant and all active sessions for the affected subject;
- successor grants and newly issued sessions use request-scoped discard
  compensation until response publication succeeds;
- remember-me evidence is marked only as a persistent_grant and never claims
  possession-factor, MFA or phishing resistance.

## Version 2 compatibility

Version 2.0.0 requires `componenta/auth-session-http ^2.0.1`. Its browser
security contract uses `componenta/http-csrf-middleware ^3.0`, which validates
Origin/Referer on unsafe requests and rejects missing origin metadata by
default. Upgrade the session HTTP and CSRF packages together; do not disable
origin validation to preserve older clients.

See [the changelog](CHANGELOG.md) for migration details. Session issuance
continues to use the shared Componenta Auth session APIs; this package does
not create an independent session or CSRF stack.
