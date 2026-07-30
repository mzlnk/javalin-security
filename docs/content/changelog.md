# Release notes

Notable changes to `javalin-security`. This changelog follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - Unreleased

_Current version: `{{ versions.library }}`._

Nothing has shipped yet, so this is the first release. It is versioned `2.0.0` because the
extension API went through two breaking redesigns before release: the concrete-identity classes
(`BasicUser`, `ApiKey`, `OpaqueToken`, `Session`) were first replaced with a generic-on-identity
design (`basicAuth<User> { }`), and the generic parameter has now been dropped from every
extension in favour of using the `Identity` interface directly in the SPI. Identity types are
brought by the caller and read back with `ctx.identity<T>()` — an unchecked cast, like
`ctx.attribute<T>()`.

### Extension API — no generic on the factory

- **No `<I>` on the factory.** `basicAuth { }`, `apiKey { }`, `opaqueToken { }`, `session { }`,
  and `jwt { }` are all non-generic. Configure `userLookup` / `lookup` / `sessionManager` /
  `identityMapper` with your own `Identity` type; read it back with `ctx.identity<YourType>()`.
- **Non-generic SPI types.** `PasswordCredentials`, `TokenRecord`, `UserLookup`, `ApiKeyLookup`,
  `OpaqueTokenLookup`, `JwtIdentityMapper`, `SessionManager`, and `HttpSessionManager` are all
  non-generic — their identity field / return value is typed as `Identity`.
- **`HttpSessionManager` Serializable check.** The default session manager now checks
  `identity is Serializable` at create time and throws `IllegalArgumentException` with a
  descriptive message when it isn't — the same guarantee the previous compile-time bound
  provided, surfaced eagerly at `SessionManager.create(...)` instead of at replication time.
- **Single `jwt { }` overload.** The generic `jwt<I> { }` overload (and the Java
  `JwtSecurity.jwtWithIdentity(...)` companion) is gone; set `identityMapper` on the same
  non-generic `jwt { }` block to map verified tokens to your own domain identity. The default
  path (no `identityMapper`) still attaches the built-in `Jwt` identity.

### Basic Auth encoded password is not on the identity

- `UserLookup` returns `PasswordCredentials` (identity + encoded password kept separate), so the
  encoded password used for verification is never reachable via `ctx.identity<I>()`.

### Session

- Ships a default `HttpSessionManager` — `session { }` works with zero configuration.
- Session create/invalidate is the caller's responsibility: keep a reference to your
  `SessionManager` and call `create` / `invalidate` from login/logout handlers. The strategy
  only validates sessions on each request.
- Default `HttpSessionManager` rotates the session id on create for session-fixation defense.

### Added

- **Core** (`javalin-security`): HTTP and WebSocket guards (installed with the plugin),
  `security { }` configuration, `authentication()` / `identity()` / `identityOrNull()`
  accessors, `PasswordCredentials`, `AuthenticationStrategy.sync` / `.async` factory helpers.
- **Authentication SPI**: sync and async strategies, `AuthenticationResult`, `Identity`,
  unauthorized handlers.
- **Authorization**: built-in rules, rule tables, `Anyone`, deny-by-default fallback, path
  patterns (Javalin syntax), CORS preflight bypass.
- **WebSocket**: Origin allow-listing at upgrade.
- **Basic Auth** (`javalin-security-basic-auth`): `basicAuth { }`, user lookup returning
  `PasswordCredentials`, password encoder, optional `WWW-Authenticate` challenge.
- **API Key** (`javalin-security-api-key`): `apiKey { }`, key lookup, header/query/cookie
  resolvers.
- **Opaque Token** (`javalin-security-opaque-token`): `opaqueToken { }`, token lookup returning
  `TokenRecord`, expiry validation, optional `WWW-Authenticate: Bearer` challenge.
- **Session** (`javalin-security-session`): `session { }` with a default `HttpSessionManager`,
  session-id rotation on create, runtime `Serializable` check on the default manager.
  Callers wire `SessionManager.create` / `invalidate` themselves.
- **JWT** (`javalin-security-jwt`): single `jwt { }` factory — default `Jwt` identity, opt into
  your own via `identityMapper`; decoder SPI, key sources, roles mapping, optional bearer
  challenge.
- **Decoder adapters**: Nimbus and Auth0 (JWKS caching, RSA / EC / HMAC).
- Java interoperability across modules.

### Compatibility

- Java **17+**, Javalin **{{ versions.javalin_family }}**, Kotlin **{{ versions.kotlin_family }}**.

!!! note "Pre-release"
    While the version is `{{ versions.library }}`, the public API may still change before the
    first stable release.
