# Error handling

When access is denied, the security guard hands the response over to one of two hooks carried by
the active [`AuthenticationStrategy`](authentication.md). Both are single-method functional
interfaces — their only job is to **render the response**. The guard has already made the
decision and will skip the remaining handlers on the route.

| Hook                  | Invoked when                                                                 | Default response  |
|-----------------------|------------------------------------------------------------------------------|-------------------|
| `UnauthorizedHandler` | Authentication produced a `Failure`, or an anonymous caller was denied.      | bare **401**      |
| `ForbiddenHandler`    | An **authenticated** caller was denied.                                      | bare **403**      |

## `UnauthorizedHandler`

Renders the response for callers that are **not authenticated** — either because credentials were
missing (anonymous) or because they were present but invalid (`AuthenticationResult.Failure`).

```kotlin
fun interface UnauthorizedHandler {
    fun handle(context: Context, failure: AuthenticationResult.Failure?)
}
```

- `context` — the current request; call `status(...)`, `json(...)`, `header(...)`, etc.
- `failure` — non-`null` when authentication failed (bad credentials, invalid or expired token);
  `null` when the caller was simply anonymous. Use it to distinguish the two cases **in logs**,
  never in the response body.

The default raises a bare `401 Unauthorized`.

## `ForbiddenHandler`

Renders the response for an **authenticated** caller who is not allowed to access the resource —
their identity is known, but their roles or the rule table reject the request.

```kotlin
fun interface ForbiddenHandler {
    fun handle(context: Context, authentication: Authentication)
}
```

- `context` — the current request; render however you need.
- `authentication` — the caller's resolved [`Authentication`](authentication.md) (identity +
  roles). Useful for audit logging or personalized error bodies.

The default raises a bare `403 Forbidden`.

## Configured on the strategy

Both hooks are members of `AuthenticationStrategy`, so **every strategy — built-in or custom —
controls how its 401 / 403 responses look**:

```kotlin
sealed interface AuthenticationStrategy {
    val unauthorizedHandler: UnauthorizedHandler get() = UnauthorizedHandler.DEFAULT
    val forbiddenHandler: ForbiddenHandler get() = ForbiddenHandler.DEFAULT
    // ...
}
```

A strategy may override either hook (or both) to plug in richer responses — JSON error envelopes,
`WWW-Authenticate` challenges, redirects, and so on. When neither is overridden, the guard falls
back to the plain 401 / 403 defaults. See [Authentication](authentication.md) for how a strategy
is assigned to `http.authentication` / `ws.authentication`.

!!! danger "Never echo failure detail"
    Do not write `failure.message` or exception text into the response body. That helps attackers
    enumerate users and probe tokens. Log the reason server-side; keep the response opaque.
