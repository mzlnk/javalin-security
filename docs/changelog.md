# Release notes

Notable changes to `javalin-security`. This changelog follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Current version: `1.0.0-SNAPSHOT`._

### Added

- **Core** (`javalin-security`): opt-in HTTP and WebSocket guards, `security { }` configuration,
  `authentication()` / `identity()` accessors.
- **Authentication SPI**: sync and async strategies, `AuthenticationResult`, `Identity`,
  unauthorized handlers.
- **Authorization**: built-in rules, rule tables, `Anyone`, deny-by-default fallback, path
  patterns (Javalin syntax), CORS preflight bypass.
- **WebSocket**: Origin allow-listing at upgrade.
- **Basic Auth** (`javalin-security-basic-auth`): `basicAuth { }`, user lookup, password
  encoder, optional `WWW-Authenticate` challenge.
- **JWT** (`javalin-security-jwt`): `jwt { }`, decoder SPI, key sources, roles mapping, optional
  bearer challenge.
- **Decoder adapters**: Nimbus and Auth0 (JWKS caching, RSA / EC / HMAC).
- Java interoperability across modules.

### Compatibility

- Java **17+**, Javalin **7.2.x**, Kotlin **2.4**.

!!! note "Pre-release"
    While the version is `1.0.0-SNAPSHOT`, the public API may still change before the first
    stable release.
