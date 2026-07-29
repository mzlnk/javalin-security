# Release notes

Notable changes to `javalin-security`. This changelog follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Current version: `{{ versions.library }}`._

### Added

- **Core** (`javalin-security`): HTTP and WebSocket guards (installed with the plugin),
  `security { }` configuration, `authentication()` / `identity()` / `identityOrNull()`
  accessors.
- **Authentication SPI**: sync and async strategies, `AuthenticationResult`, `Identity`,
  unauthorized handlers.
- **Authorization**: built-in rules, rule tables, `Anyone`, deny-by-default fallback, path
  patterns (Javalin syntax), CORS preflight bypass.
- **WebSocket**: Origin allow-listing at upgrade.
- **Basic Auth** (`javalin-security-basic-auth`): `basicAuth { }`, user lookup, password
  encoder, optional `WWW-Authenticate` challenge.
- **API Key** (`javalin-security-api-key`): `apiKey { }`, key lookup, header/query/cookie resolvers.
- **JWT** (`javalin-security-jwt`): `jwt { }`, decoder SPI, key sources, roles mapping, optional
  bearer challenge.
- **Decoder adapters**: Nimbus and Auth0 (JWKS caching, RSA / EC / HMAC).
- Java interoperability across modules.

### Compatibility

- Java **17+**, Javalin **{{ versions.javalin_family }}**, Kotlin **{{ versions.kotlin_family }}**.

!!! note "Pre-release"
    While the version is `{{ versions.library }}`, the public API may still change before the
    first stable release.
