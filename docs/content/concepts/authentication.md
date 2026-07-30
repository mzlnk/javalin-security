# Authentication

Authentication answers **"who is calling?"**. A strategy inspects the request and produces an
`Authentication` (identity + roles) that [authorization](authorization.md) then uses.

You usually do not implement this yourself — assign a strategy from
[Basic Auth](../extensions/basic-auth.md), [JWT](../extensions/jwt/index.md), or a
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

## Identity

`Authentication` wraps an optional `Identity` (the caller) and a set of `RouteRole`s. `Identity`
itself declares `name` and `roles`. Every extension attaches whichever `Identity` your lookup /
mapper returns — Basic Auth, API Key, Opaque Token, and Session take yours directly. JWT
defaults to its own `Jwt` identity (wrapping the verified token and its `rolesMapper`-derived
roles), or your own type when you configure an `identityMapper`. A custom scheme implements
`Identity` — including `roles` — in the same way. Cast with `ctx.identity<YourType>()` (checked
at runtime, like `ctx.attribute<T>()`).

`Authentication.authenticated(identity)` takes a single `Identity` argument and derives
`Authentication.roles` from `identity.roles`; there is no separate roles parameter.

| Member            | Meaning                                    |
|-------------------|--------------------------------------------|
| `identity`        | Who is calling (`null` when anonymous).    |
| `roles`           | Granted roles (empty when anonymous), taken from `identity.roles`. |
| `isAuthenticated` | `true` when `identity != null`.            |

## Reading auth in handlers

Use `ctx.authentication()` (never `null`), `ctx.identity<T>()` (throws when anonymous), or
`ctx.identityOrNull<T>()` (`null` when anonymous). The same accessors are available on
`WsContext` after a successful upgrade, and auth is **not** re-checked per WebSocket message.

See [Access caller identity](../getting-started/access-caller-identity.md) for full HTTP and
WebSocket examples.

!!! tip "Sync vs async"
    Built-in Basic Auth and JWT strategies are synchronous. For remote I/O (DB lookups, remote
    IdP), implement `AuthenticationStrategy.Async` — see
    [Custom authentication](../guides/custom-authentication.md).

## Next steps

- [Authorization](authorization.md) — decide who is allowed.
- [Access caller identity](../getting-started/access-caller-identity.md) — read the caller in
  handlers.
- [Error handling](error-handling.md) — customize 401 / 403 responses.
