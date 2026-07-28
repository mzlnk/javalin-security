# Custom authorization rules

The built-in rules (`allow`, `deny`, `authenticated`, `hasRole`, `hasAnyRole`) cover the common
cases, but real applications often need decisions that depend on the request itself — the
caller's IP must be on an allowlist, the request must arrive during business hours, and so on.
`javalin-security` exposes a small `Rule` interface for exactly these cases; you can plug custom
rules into the same `http.rules { }` and `ws.rules { }` tables you already use for the
built-ins.

## What a `Rule` is

`Rule` is a single-abstract-method interface:

```kotlin
fun interface Rule {
    fun isGranted(authentication: Authentication, context: Context): Boolean
}
```

- **`authentication`** — the resolved [`Authentication`](../concepts/authentication.md) for the
  request. `authentication.identity` is `null` for anonymous callers; `authentication.roles` is
  the set of granted roles.
- **`context`** — the Javalin `Context` for HTTP rules (or the upgrade `Context` for
  WebSocket rules). Read the client IP, headers, path or query parameters, or anything else
  from it.
- **Return** `true` to grant access, `false` to deny. Never throw — an exception is treated as
  a denial and turns into 401 / 403 based on whether the caller is authenticated.

Because `Rule` is a `fun interface`, Kotlin lambdas and Java `->` lambdas both work out of the
box.

## When to reach for a custom rule

| You need to check…                             | Use…                                                     |
|------------------------------------------------|----------------------------------------------------------|
| The caller is logged in.                       | `authenticated` (built-in).                              |
| The caller has one specific role.              | `hasRole(role)` (built-in).                              |
| The caller has any of several roles.           | `hasAnyRole(...)` (built-in).                            |
| Request-time constraints (IP, time, feature).  | **Custom rule** — read from the context.                |

If the check does not depend on the request, prefer role-based authorization: grant the role in
your `Authenticator` and use `hasRole` in the rule table. Custom rules are for the cases where
role membership alone cannot answer the question.

## Example: IP allowlist

A common case: an internal admin API should only be reachable from a small set of trusted IP
addresses (an office network, a jump host, a corporate VPN). We express that as a rule that
inspects the client IP on the `Context`.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rule
    import io.github.mzlnk.javalin.security.security

    val allowedIps = setOf("10.0.0.10", "10.0.0.11", "203.0.113.42")

    val fromTrustedIp = Rule { _, ctx -> ctx.ip() in allowedIps }

    config.security { security ->
        security.http { http ->
            http.authentication = myStrategy
            http.rules { r ->
                r.add("/admin/*", fromTrustedIp)
                r.fallback = r.deny
            }
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rule;
    import io.github.mzlnk.javalin.security.authorization.Rules;

    Set<String> allowedIps = Set.of("10.0.0.10", "10.0.0.11", "203.0.113.42");

    Rule fromTrustedIp = (auth, ctx) -> allowedIps.contains(ctx.ip());

    config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
        http.authentication = myStrategy;
        http.rules(r -> {
            r.add("/admin/*", fromTrustedIp);
            r.fallback = Rules.deny();
        });
    })));
    ```

Anonymous callers whose IP is not on the list get a **401**; authenticated callers from an
unlisted IP get a **403**. See [Denial status](../concepts/authorization.md#denial-status).

!!! tip "Behind a proxy or load balancer"
    `Context.ip()` returns the socket-level peer. Behind a reverse proxy, that is the proxy's
    address — configure Javalin to trust `X-Forwarded-For` (or read the forwarded header
    directly in the rule) so you compare against the real client IP.

## WebSocket rules

`Rule` is the same type for HTTP and WebSocket authorization; you register it against
`ws.rules { }` instead of `http.rules { }`. WebSocket rules match on path only (no method), and
they run **once at upgrade time** — the resulting `Authentication` is then reused for every
message on that session.

=== "Kotlin"

    ```kotlin
    security.ws { ws ->
        ws.authentication = myWsStrategy
        ws.rules { r ->
            r.add("/ws/admin/*", fromTrustedIp)
            r.fallback = r.deny
        }
    }
    ```

=== "Java"

    ```java
    security.ws(ws -> {
        ws.authentication = myWsStrategy;
        ws.rules(r -> {
            r.add("/ws/admin/*", fromTrustedIp);
            r.fallback = Rules.deny();
        });
    });
    ```

## Rules for well-behaved rules

!!! danger "Never throw from a rule"
    A rule that throws is treated as a denial. Instead, return `false` — the guard renders the
    proper 401 or 403 based on whether the caller is authenticated. Reserve exceptions for real
    programming errors.

- **Always null-check the identity.** Anonymous callers reach custom rules too. The idiomatic
  Kotlin form is `auth.identity as? MyIdentity ?: return@Rule false`; in Java, use
  `instanceof` pattern matching.
- **Do not do I/O in a rule.** Rules run on the request thread. If you need remote lookups,
  cache the answer in the authenticator (attach it to the identity) so the rule can read it
  synchronously.
- **Keep rules pure.** No mutation, no logging of sensitive request data, no side effects on
  the `Context` — a rule only decides, the handler acts.
- **Order matters in the table.** Entries are evaluated top-to-bottom and the first match wins;
  put specific patterns before broader ones.
- **Prefer role checks when possible.** If the answer only depends on identity, put the check
  in your `Authenticator` (grant a role) and use `hasRole` — it is faster to read and easier to
  audit.

## Testing rules

Because `Rule` is a plain functional interface, you can unit-test it without spinning up
Javalin. Build an `Authentication` with `Authentication.authenticated(...)` (or
`Authentication.unauthenticated()`) and pass a mocked `Context`.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Authentication
    import io.javalin.http.Context
    import io.mockk.every
    import io.mockk.mockk
    import org.assertj.core.api.Assertions.assertThat
    import kotlin.test.Test

    class FromTrustedIpTest {

        @Test
        fun `grants when the caller IP is on the allowlist`() {
            val ctx = mockk<Context> { every { ip() } returns "10.0.0.10" }
            assertThat(fromTrustedIp.isGranted(Authentication.unauthenticated(), ctx)).isTrue()
        }

        @Test
        fun `denies when the caller IP is not on the allowlist`() {
            val ctx = mockk<Context> { every { ip() } returns "198.51.100.7" }
            assertThat(fromTrustedIp.isGranted(Authentication.unauthenticated(), ctx)).isFalse()
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authentication.Authentication;
    import io.javalin.http.Context;
    import org.junit.jupiter.api.Test;

    import static org.assertj.core.api.Assertions.assertThat;
    import static org.mockito.Mockito.mock;
    import static org.mockito.Mockito.when;

    class FromTrustedIpTest {

        @Test
        void grants_when_caller_ip_is_on_the_allowlist() {
            Context ctx = mock(Context.class);
            when(ctx.ip()).thenReturn("10.0.0.10");
            assertThat(fromTrustedIp.isGranted(Authentication.unauthenticated(), ctx)).isTrue();
        }

        @Test
        void denies_when_caller_ip_is_not_on_the_allowlist() {
            Context ctx = mock(Context.class);
            when(ctx.ip()).thenReturn("198.51.100.7");
            assertThat(fromTrustedIp.isGranted(Authentication.unauthenticated(), ctx)).isFalse();
        }
    }
    ```

For an end-to-end assertion (real server, real HTTP status), see
[Testing secured apps](testing.md).

## Next steps

- [Authorization](../concepts/authorization.md) — how the rule table fits into the request
  lifecycle.
- [Error handling](../concepts/error-handling.md) — customize the 401 / 403 responses your
  rules produce.
- [Custom authentication](custom-authentication.md) — grant custom roles or attach extra data
  to the identity so rules can read it.
