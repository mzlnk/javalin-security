---
name: javalin-security
description: Reference for adding authentication and authorization to a Javalin 7 application with the javalin-security plugin (io.github.mzlnk:javalin-security). Use whenever the task involves configuring `security.rules`, choosing or wiring an authentication strategy (Basic Auth, API Key, Opaque Token, Session, JWT), reading the caller in a handler (identity/authentication), implementing a custom `AuthenticationStrategy` or `Rule`, hardening JWT/WebSocket/CORS setup, or debugging why routes return 401/403. Do NOT trigger for unrelated Javalin questions that don't involve the security plugin.
---

# javalin-security — agent reference

Consumer-facing guidance for adding authentication and authorization to a Javalin 7
application. Assume Java 17+ and Javalin 7 basics. Current library version: **0.2.0** (pre-1.0;
breaking changes possible) — replace `<version>` in the snippets below with it. This file is
self-contained for common tasks; the [docs map](#docs-map) links per-topic pages for anything
deeper.

## Mental model

`javalin-security` is a **plugin + rule table + authentication abstractions**. Core provides no
concrete authentication mechanism. For each channel (`security.http` and `security.ws`), assign
one ready-made strategy or implement `AuthenticationStrategy`; reassignment is last-write-wins.
HTTP and WebSocket strategies are independent.

Prefer a shipped extension when its scheme fits:

| Need | Extension |
|---|---|
| Username + password | Basic Auth |
| Static machine key | API Key |
| Server-issued bearer token | Opaque Token |
| Cookie-backed login session | Session |
| OIDC/OAuth2 JWT | JWT + one decoder adapter |
| mTLS, HMAC, proprietary protocol | Custom `AuthenticationStrategy` |

## Install

All artifacts share the group `io.github.mzlnk` and one version. Maven coordinates use the same
group/artifact/version. Your application must already provide Javalin and an SLF4J binding — they
are `compileOnly` in the library. Extensions pull core in transitively (`api`), but declare core
explicitly for clarity.

```kotlin
implementation("io.github.mzlnk:javalin-security:<version>")              // core — always
implementation("io.github.mzlnk:javalin-security-basic-auth:<version>")   // Basic Auth
implementation("io.github.mzlnk:javalin-security-api-key:<version>")      // API Key
implementation("io.github.mzlnk:javalin-security-opaque-token:<version>") // Opaque Token
implementation("io.github.mzlnk:javalin-security-session:<version>")      // Session
implementation("io.github.mzlnk:javalin-security-jwt:<version>")          // JWT contracts
implementation("io.github.mzlnk:javalin-security-jwt-nimbus:<version>")   // JWT: Nimbus adapter…
implementation("io.github.mzlnk:javalin-security-jwt-auth0:<version>")    // …OR Auth0 adapter
```

JWT needs the contracts plus exactly ONE adapter (the adapter brings the contracts transitively).
Adapters do NOT bundle their third-party libraries — add them yourself: Nimbus →
`com.nimbusds:nimbus-jose-jwt` (10.x line, minimum 10); Auth0 → `com.auth0:java-jwt` (4.x line,
minimum 4) and `com.auth0:jwks-rsa` (minimum 0.24). Choose current stable releases; avoid dynamic
`+` versions in production builds.

## Minimal wiring

Registering the plugin installs **both** HTTP and WebSocket guards. With no strategy, callers are
anonymous; with no matching rule, each guard uses its non-null fallback (`http.fallback` and
`ws.fallback`, both initialized to `Rules.deny()`). `security.rules` is shared by HTTP entries
and `rules.ws(...)` entries.

```kotlin
import io.github.mzlnk.javalin.security.authorization.Rules

Javalin.create { config ->
    config.security { security ->
        security.rules.get("/public/*", Rules.allow())
        security.rules.post("/api/*", Rules.authenticated())
        security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN))

        security.http.authentication = myStrategy    // from an extension factory (below) or custom
        security.http.fallback = Rules.deny() // optional: this is already the default
    }
    config.routes.get("/api/me") { it.result(it.identity<User>().name) }
}.start(7070)
```

Java uses `new JavalinSecurityPlugin(security -> ...)` registered via `config.registerPlugin`,
`Rules.*`, and static helpers from `SecurityExtensions`.

## Wiring each extension

Each extension exposes a top-level Kotlin factory that returns an `AuthenticationStrategy`;
assign it to `security.http.authentication` (JWT also fits `security.ws.authentication`; Basic
Auth and Session are HTTP-only). Java mirrors are static methods:
`BasicAuthSecurity.basicAuth(...)`, `ApiKeySecurity.apiKey(...)`,
`OpaqueTokenSecurity.opaqueToken(...)`, `SessionSecurity.session(...)`, `JwtSecurity.jwt(...)`.

```kotlin
// Basic Auth — package io.github.mzlnk.javalin.security.basicauth
security.http.authentication = basicAuth { basic ->
    basic.userLookup = UserLookup { username -> users[username] }  // required: → BasicUserDetails(identity, encodedPassword, roles) or null
    basic.passwordEncoder = myBcryptEncoder                        // default noOp() — replace in production
}

// API Key — package io.github.mzlnk.javalin.security.apikey
security.http.authentication = apiKey { api ->
    api.lookup = ApiKeyLookup { raw -> keys[raw] }   // required: → ApiKeyDetails(identity, roles) or null
    // api.resolver defaults to the X-Api-Key header; also ApiKeyResolver.header/query/cookie(...)
}

// Opaque Token — package io.github.mzlnk.javalin.security.opaquetoken
security.http.authentication = opaqueToken { ot ->
    ot.lookup = OpaqueTokenLookup { raw -> tokens[raw] }  // required: → OpaqueTokenDetails(identity, expiresAt?, roles) or null
    // ot.resolver defaults to Authorization: Bearer; expiresAt validated against ot.clock
}

// Session — package io.github.mzlnk.javalin.security.session
val sessionManager = HttpSessionManager.of()          // keep ONE instance; identity must be Serializable
security.http.authentication = session { s ->
    s.sessionManager = sessionManager                 // default HttpSessionManager.of() when omitted
}
// login handler:  sessionManager.create(ctx, SessionDetails(User("alice"), setOf(Role.USER)))
// logout handler: sessionManager.invalidate(ctx)

// JWT — package io.github.mzlnk.javalin.security.jwt (+ adapter package)
security.http.authentication = jwt { jwt ->
    jwt.decoder = NimbusJwtDecoder                    // required; Java: NimbusJwtDecoder.INSTANCE (or Auth0JwtDecoder)
    jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json") // required
    jwt.issuer = "https://issuer.example.com/"        // recommended: enforce iss
    jwt.audiences = setOf("my-api")                   // recommended: enforce aud
    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name -> Role.entries.find { it.name == name } }
}
```

`JwtKeySource` factories: `jwks(url)` (OIDC issuers, keys matched by `kid`, cached),
`pem(string)` / `pemFile(path)` (X.509/PKCS#8 public key), `publicKey(key, algorithms?)`,
`secret(string, algorithm?)` / `secretBytes(bytes, algorithm?)` (HMAC, default `HS256`).

## Core concepts

- `AuthenticationStrategy.Sync` / `.Async`: how callers are identified. Convenience factories
  `AuthenticationStrategy.sync(...)` / `.async(...)` build one from an authenticator lambda.
- `AuthenticationResult`: `Success`, `Failure` (immediate 401), or `NotAuthenticated`
  (anonymous; authorization decides).
- `Identity`: who is calling; application-defined and exposes `name`.
- `Authentication`: identity, roles, and `isAuthenticated`. Factories:
  `Authentication.authenticated(identity, roles)` and `Authentication.unauthenticated()`.
- `Rule` / `Rules`: authorization predicate and built-ins (`allow`, `deny`, `authenticated`,
  `hasRole`, `hasAnyRole` — the complete list).
- `Anyone`: route-role equivalent of `Rules.allow()`.
- `TokenResolver` (shared by Opaque Token and JWT): `bearerHeader()` (default),
  `bearerHeader("X-Custom")`, `cookie(name)`.

## Reading the caller in handlers

Kotlin — import from `io.github.mzlnk.javalin.security`:

```kotlin
val auth = ctx.authentication()                // never null; anonymous when no credentials
val user = ctx.identity<User>()                // throws when anonymous — use behind authenticated/hasRole
val userOrNull = ctx.identityOrNull<User>()    // null when anonymous
```

Java uses static `SecurityExtensions.authentication(ctx)`, `identity(ctx, User.class)`, and
`identityOrNull(ctx, User.class)`.

These accessors also work on `WsContext`. Authentication is resolved once at upgrade and reused
for the session; it is not re-checked per message.

## Rule table — non-obvious semantics (MUST follow)

- **First match wins.** Put specific patterns before broader ones (`/api/admin/*` before `/api/*`).
- **Deny by default.** `http.fallback` and `ws.fallback` are non-null and initialized to
  `Rules.deny()`; replace one only when unmatched routes should follow another policy.
- **Route roles win over the table.** If a route declares any `RouteRole` (including `Anyone`),
  the rule table AND `fallback` are SKIPPED for that route. Do NOT mix a `security.rules` entry
  and route-declared roles for the same route expecting both to run — only the roles fire.
- **A `GET` rule also governs `HEAD`.** Do not add a separate `head` entry unless you truly need one.
- **WebSocket rules match path only.** Use `security.rules.ws(pattern, rule)`.
- **Path syntax is Javalin route syntax.** Only `*`, `{param}`, `<param>`. Ant-style `**` and
  `?` are REJECTED at startup with `SecurityConfigurationException`.
- **Denial status.** Anonymous denied → **401**; authenticated denied → **403**.
- **CORS preflight bypass**: set `security.http.allowCorsPreflight = true` AND register
  Javalin's CORS plugin (`config.bundledPlugins.enableCors { … }`) for response headers.
  The bypass only exempts `OPTIONS` requests carrying `Access-Control-Request-Method`.

### Verbs and grouped declaration

HTTP entries support `get`, `post`, `put`, `patch`, `delete`, `head`, `options`, and `any`.
For shared path prefixes use the nested DSL (Java: `security.rules.apiBuilder(() -> ...)` with
static imports from `SecurityApiBuilder`):

```kotlin
security.rules.apiBuilder {
    path("/api/v1") {
        get("/*", Rules.allow())
        post("/*", Rules.authenticated())
        delete("/*", Rules.hasRole(Role.ADMIN))
    }
    ws("/ws/chat", Rules.authenticated())
}
```

## Extension guardrails — CRITICAL FOR PRODUCTION

- **Basic Auth**: `PasswordEncoder.noOp()` performs constant-time plaintext comparison, not
  hashing. Use BCrypt, Argon2, or PBKDF2 and store only encoded passwords.
- **API Key / Opaque Token**: hash secrets at rest and compare in constant time inside the lookup.
  Return `null` to reject or revoke a credential.
- **Session**: the default manager requires a `Serializable` identity. Keep the same
  `SessionManager` instance for configuration and login/logout `create` / `invalidate` calls.
- **JWT roles**: default `JwtRolesMapper.noRoles()` grants no roles. Configure `fromClaim`,
  `fromScope`, or a custom mapper before using role rules.
- **JWT identity**: handlers receive `Jwt` by default. Set `identityMapper` for a domain identity;
  `null` fails authentication. It may be combined with `rolesMapper`.
- **JWT PEM keys must be X.509 / PKCS#8** (`-----BEGIN PUBLIC KEY-----`). PKCS#1 RSA PEMs
  (`-----BEGIN RSA PUBLIC KEY-----`) are rejected with `IllegalArgumentException`.
- **JWT over browser WebSockets**: browsers can't set `Authorization` on the WS handshake.
  Carry the JWT in an `HttpOnly Secure` cookie via `jwt.tokenResolver = TokenResolver.cookie("access_token")`
  AND set `security.ws.allowedOrigins` (otherwise the socket is open to cross-site WebSocket hijacking).
- **WebSocket `allowedOrigins`**: when set, missing or unlisted `Origin` values are rejected
  before authentication. Empty or blank values fail at startup; leave it unset to disable.

## Custom `AuthenticationStrategy` (only when no extension fits)

Do:
- Return `AuthenticationResult.NotAuthenticated` when NO credentials are present.
- Return `AuthenticationResult.Failure("reason")` when credentials are present but invalid.
- Wrap remote I/O in `AuthenticationStrategy.Async` — HTTP releases the request thread via `Context.future`.
- Attach an app-specific `Identity` implementation (exposes `name`, plus extra fields as needed).
- Grant roles via `Authentication.authenticated(identity, setOf(Role.X))`.

Do not:
- Return `Failure` for missing credentials — every public route would return 401.
- Throw from an authenticator. Sync exceptions propagate to Javalin; async exceptions are
  converted to `Failure` and normally produce 401. Return an explicit `Failure` for invalid
  credentials and handle operational errors deliberately.
- Write `failure.message` or exception text into the response body — that leaks reasons to attackers. Log server-side only.
- Do blocking I/O in `Sync` — use the `Async` variant.

## Custom `Rule` (request-time predicate)

Use a custom `Rule` for IP allowlists, tenant ownership, business hours — checks that depend
on the REQUEST, not identity alone. If the answer depends only on identity, grant a role in
your authenticator and use `Rules.hasRole(...)` instead — faster to read and easier to audit.

```kotlin
val fromTrustedIp = Rule { _, ctx -> ctx.ip() in setOf("10.0.0.10", "10.0.0.11") }
security.rules.any("/admin/*", fromTrustedIp)
```

Rules must not throw or perform I/O: they run on the request thread, and exceptions propagate to
Javalin rather than becoming a denial. Null-check `authentication.identity`; anonymous callers
reach custom rules.

## Error rendering

Customize `unauthorizedHandler` and `forbiddenHandler` on the strategy (every extension config
exposes them), not the guard. Never send `failure.message` or exception details to clients; log
them server-side.

## Testing

Use `javalin-testtools` compatible with your Javalin release. Build the app in a factory and assert
real 200/401/403 responses. For WebSocket denial, inspect
`WebSocketHandshakeException.getResponse().statusCode()`. Unit-test custom rules with both
authenticated and anonymous callers.

## Troubleshooting

- JWT role checks fail: configure `rolesMapper`; its default grants no roles.
- Every route returns 401: return `NotAuthenticated` when credentials are absent.
- Ant-pattern startup error: replace `**` / `?` with Javalin route syntax.
- CORS preflight returns 401: enable `allowCorsPreflight` and Javalin's CORS plugin.
- Browser WebSocket JWT fails: use an `HttpOnly Secure` cookie and set `ws.allowedOrigins`.
- Identity cast fails: read the type attached by the strategy, or configure JWT `identityMapper`.
- `NoClassDefFoundError`: add required Javalin, SLF4J, or decoder runtime dependencies.

## Docs map

Base URL: `https://mzlnk.github.io/javalin-security/` — fetch the page for the topic at hand:

- Getting started: `getting-started/installation/`, `getting-started/secure-endpoints/`,
  `getting-started/access-caller-identity/`
- Concepts: `concepts/authentication/`, `concepts/authorization/`, `concepts/error-handling/`
- Extensions: `extensions/basic-auth/`, `extensions/api-key/`, `extensions/opaque-token/`,
  `extensions/session/`
- JWT: `extensions/jwt/configuration/`, `extensions/jwt/nimbus/`, `extensions/jwt/auth0/`,
  `extensions/jwt/key-sources/`, `extensions/jwt/roles-mapping/`
- Guides: `guides/custom-authentication/`, `guides/custom-rules/`, `guides/cors/`, `guides/testing/`
- Reference: `rules/` (rules DSL), `http-security/`, `websocket-security/`, `api/` (KDoc)
