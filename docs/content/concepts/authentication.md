# Authentication

Authentication answers **"who is calling?"**. An `AuthenticationStrategy` inspects the request
and produces an `Authentication` (identity + roles) that [authorization](authorization.md) then
uses.

You usually do not implement this yourself — assign a strategy from
[Basic Auth](../extensions/basic-auth.md), [JWT](../extensions/jwt/configuration.md), or a
[custom authenticator](../guides/custom-authentication.md).

## Assigning a strategy

Any `AuthenticationStrategy` can be assigned to `http.authentication` or `ws.authentication`:

=== "Kotlin"

    ```kotlin
    http.authentication = basicAuth { it.userLookup = myLookup }
    http.authentication = jwt { it.decoder = NimbusJwtDecoder; it.keySource = keys }
    ```

=== "Java"

    ```java
    http.authentication = BasicAuthSecurity.basicAuth(cfg -> cfg.userLookup = myLookup);
    http.authentication = JwtSecurity.jwt(cfg -> {
        cfg.decoder = NimbusJwtDecoder.INSTANCE;
        cfg.keySource = keys;
    });
    ```

Leaving `authentication` unset is valid: every caller is **anonymous**, and the rule table alone
decides access.

## Anatomy of a strategy

`AuthenticationStrategy` is a sealed type with two variants. Both carry the same optional handlers
for rendering failures; they differ only in how authentication runs:

| Variant                     | Authenticator            | When to use                                              |
|-----------------------------|--------------------------|----------------------------------------------------------|
| `AuthenticationStrategy.Sync`  | `Authenticator`       | Blocking work on the request thread (typical).           |
| `AuthenticationStrategy.Async` | `AsyncAuthenticator` | Remote I/O (DB lookups, IdP calls) that should not block.|

The authenticator is the piece that looks at the request and returns an `AuthenticationResult`
(see [Three outcomes](#three-outcomes)). Sync authenticators return the result directly; async
ones return a `CompletableFuture` of the same type.

A strategy also exposes:

| Member                | Role                                                              |
|-----------------------|-------------------------------------------------------------------|
| `authenticator()`     | Resolves who is calling.                                          |
| `unauthorizedHandler` | Renders failed or absent authentication (default: bare HTTP 401). |
| `forbiddenHandler`    | Renders access denied for an authenticated caller (default: 403). |

Prefer `AuthenticationStrategy.Async` when authentication performs remote I/O and the request
thread should be released while that work is in flight.

## Three outcomes

An authenticator returns one of three results:

| Result             | Meaning                                | Effect                                                       |
|--------------------|----------------------------------------|--------------------------------------------------------------|
| `Success`          | Credentials valid                      | Continue with identity + roles.                              |
| `NotAuthenticated` | No credentials present                 | Continue as anonymous.                                       |
| `Failure`          | Credentials present but invalid        | Immediate **401** (reason logged, never sent to the client). |

!!! danger "`NotAuthenticated` vs `Failure`"
    Missing credentials must be `NotAuthenticated` — otherwise every public route becomes a 401.
    Reserve `Failure` for bad passwords, expired tokens, or malformed headers.

## Identity and roles

`Authentication` is the security token for a request. It holds an optional `Identity` (who is
calling) and a set of `RouteRole`s (what they may do). Those concerns stay separate:

- **`Identity`** answers “who?”. It declares only `name` — a human-readable identifier such as a
  username or subject. Concrete types may add scheme-specific fields, but roles are not part of
  the interface.
- **`Authentication.roles`** answers “with which rights?”. Roles are owned by `Authentication`
  and are supplied when the token is built via `Authentication.authenticated(identity, roles)`
  (`roles` defaults to empty when omitted).

Cast the identity with `ctx.identity<YourType>()` (checked at runtime, like `ctx.attribute<T>()`).

| Member            | Meaning                                    |
|-------------------|--------------------------------------------|
| `identity`        | Who is calling (`null` when anonymous).    |
| `roles`           | Granted roles (empty when anonymous).      |
| `isAuthenticated` | `true` when `identity != null`.            |

## Reading auth in handlers

Use `ctx.authentication()` (never `null`), `ctx.identity<T>()` (throws when anonymous), or
`ctx.identityOrNull<T>()` (`null` when anonymous). The same accessors are available on
`WsContext` after a successful upgrade, and auth is **not** re-checked per WebSocket message.

See [Access caller identity](../getting-started/access-caller-identity.md) for full HTTP and
WebSocket examples.

## Next steps

- [Authorization](authorization.md) — decide who is allowed.
- [Access caller identity](../getting-started/access-caller-identity.md) — read the caller in
  handlers.
- [Error handling](error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — implement your own strategy.
