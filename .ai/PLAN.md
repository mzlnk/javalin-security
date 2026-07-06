# Plan: Aligning `javalin-security` with the "Why Javalin" Vision

> Status: proposal / input for a later implementation plan.
> Scope: design + API-shape changes only. This document explains **what** to change and **why**, with concrete before/after API sketches. It intentionally does **not** contain a task-by-task implementation breakdown — that will be derived from this document.

## 1. Purpose

The current `javalin-security` MVP is a well-built, security-conscious core, but its public shape leans Spring-style rather than Javalin-style. This plan realigns the library against the six pillars advertised on [javalin.io](https://javalin.io/) ("Why Javalin": **Simple, Lightweight, Interoperable, Flexible, OpenAPI, Jetty**), while preserving the existing core strengths:

- deny-by-default authorization,
- authorization evaluated against the matched route template (bypass-proof),
- ordering-independent reading of router config at startup,
- fail-closed request handling,
- minimal, auditable runtime (one `beforeMatched` guard, no reflection, no thread-locals).

**Non-negotiable constraint:** none of the changes below may weaken those five security properties.

## 2. Gap summary (from the "Why Javalin" evaluation)

| Pillar | Current state | Target |
| --- | --- | --- |
| Simple | Met | Keep |
| Lightweight | Met | Keep |
| Jetty / runs on Javalin | Met | Keep |
| **Interoperable (Java == Kotlin)** | **Not met** — Kotlin-first DSL, awkward from Java | First-class Java API alongside the Kotlin DSL |
| **Flexible (blocking by default, async when needed)** | **Partially met** — blocking only | Optional async authentication path |
| **Config style ("same file", inline `config.x`)** | **Diverges** — separate `JavalinSecurityConfig` class + `configureSecurity(instance)` | Inline `config.security { ... }` as the primary path |

Two additional ecosystem frictions to fix along the way:

- CORS preflight / `OPTIONS` is denied by default (breaks browser CORS out of the box).
- The guard is not guaranteed to be the first `beforeMatched` handler.

## 3. Design principles for this alignment

1. **Inline-first, class-optional.** Match Javalin's "declare your server and API in the same file" identity. The separate-config-class approach stays supported but demoted to a secondary overload.
2. **One immutable model, multiple front-ends.** The Kotlin DSL, a future Java builder, and the config-class form must all converge on the same immutable `JavalinSecurity` object. The build/validation logic lives in one place.
3. **Interop by construction, not by afterthought.** Every public entry point must have a clean Java call site (no `return Unit.INSTANCE`, no `INSTANCE.getX()` for common operations).
4. **Keep the plugin core thin.** Additions are front-end ergonomics and optional capabilities; the runtime guard stays small.
5. **No silent behavior changes.** Anything that affects protection (CORS default, provider chain semantics) must be explicit and documented.

## 4. Workstreams

### 4.1 Inline configuration namespace (config style) — highest priority

**Problem.** Users must implement `JavalinSecurityConfig` in a separate class and pass an instance to `config.configureSecurity(SecurityConfig())`. This is a Spring idiom (`WebSecurityConfigurerAdapter`-like), not a Javalin one. Javalin configures inline: `config.routes.apiBuilder { }`, `config.useVirtualThreads = true`, etc.

**Target (Kotlin).**

```kotlin
Javalin.create { config ->
    config.security {
        http {
            authorizeRequests {
                authorize("/api/v1/**", GET, permitAll)
                authorize("/api/v1/**", POST, authenticated)
                anyRequest(denyAll)
            }
        }
    }
    config.routes.get("/api/v1/resource") { it.result("ok") }
}
```

**Design notes.**
- Add an extension `fun JavalinConfig.security(init: JavalinSecurity.Dsl.() -> Unit)` that builds the immutable `JavalinSecurity` and registers `JavalinSecurityPlugin` internally. This becomes the documented primary path.
- **Keep** `fun JavalinConfig.configureSecurity(config: JavalinSecurityConfig)` as a thin secondary overload for teams that prefer externalizing config into a class (delegates to the same builder). Consider deprecating `JavalinSecurityConfig` only after the inline form is proven; for now, retain it.
- Both paths must produce identical `JavalinSecurity` and register the plugin exactly once (the non-repeatable plugin already fails fast on double registration — verify this still holds when both forms are mixed and document that mixing is unsupported).
- Retain the existing startup wiring (`onStart` reading router config) unchanged — this is the security property we must not break.

**Files touched (indicative):** `extensions.kt` (new `security { }` entry point), `JavalinSecurity.kt` (DSL already exists), docs/samples, `sandbox/application.kt` migrated to the inline form as the reference example.

**Acceptance:** the README/sandbox primary example uses `config.security { }`; the class-based form still compiles and behaves identically.

### 4.2 First-class Java API (interoperability) — highest priority

**Problem.** The Kotlin DSL is hostile from Java:
- receiver lambdas compile to `Function1<Dsl, Unit>` → callers must `return Unit.INSTANCE;`,
- unqualified DSL members (`permitAll`, `hasRole(...)`) become `AuthorizationRules.INSTANCE.getPermitAll()` / instance calls,
- `configureSecurity` is a static `ExtensionsKt.configureSecurity(...)` call.

**Target (Java).**

```java
Javalin.create(config -> {
    JavalinSecurity security = JavalinSecurity.builder()
        .http(http -> http
            .authorizeRequests(auth -> auth
                .authorize("/api/v1/**", GET, Rules.permitAll())
                .authorize("/api/v1/**", POST, Rules.authenticated())
                .anyRequest(Rules.denyAll()))
            .authenticationProvider(myProvider))
        .build();

    JavalinSecuritySupport.enable(config, security); // Java-friendly install entry point
    config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
});
```

**Design notes.**
- Introduce a **fluent, `Consumer`-based Java builder** (`JavalinSecurity.builder()` returning a builder whose methods take `Consumer<...>` and return `this`). Each nested block (`http`, `authorizeRequests`) takes a `Consumer<XxxBuilder>` so Java never returns `Unit`.
- Expose built-in rules through a **Java-friendly factory with static methods** (e.g. `Rules.permitAll()`, `Rules.hasRole("ADMIN")`) that return the same `AuthorizationRule` instances as the Kotlin `AuthorizationRules` object. Kotlin keeps its unqualified DSL members; Java uses the static factory. One source of truth for the rule logic (the existing `AuthorizationRules`), two ergonomic surfaces.
- Provide a Java-friendly install entry point (a plain static method, e.g. `JavalinSecuritySupport.enable(config, security)`) so Java users don't call the Kotlin extension as `ExtensionsKt.security(...)`. Kotlin users keep `config.security { }`.
- Keep `@JvmStatic` / `@JvmOverloads` discipline already present on `Authentication`; extend it to any new factory/companion used from Java.
- **No clash rule:** the Kotlin DSL (`JavalinSecurity.Dsl`, receiver lambdas) and the Java builder must be *separate types* that both feed the same internal `build()`. Do not try to make one type serve both — that is what produces the awkward call sites. This is feasible today because build/validation is already separated from the DSL receivers.

**Interop parity requirement.** Add a compiled Java sample (or Java test source set) exercising: inline-ish setup, all built-in rules, a custom `AuthenticationProvider` (lambda), a custom `AuthorizationRule` (lambda), custom entry point / denied handler. This sample is the guardrail that keeps Java ergonomics from regressing and directly satisfies Javalin's "built the same way in both languages" claim.

**Files touched (indicative):** new Java-facing builder types (can be Kotlin classes designed for Java call sites), new `Rules` façade, install support object, new Java test/sample module.

**Acceptance:** the Java sample compiles with no `Unit.INSTANCE`, no `.INSTANCE.getX()` for common operations, and produces a `JavalinSecurity` equivalent to the Kotlin DSL.

### 4.3 Async authentication path (flexibility)

**Problem.** `AuthenticationProvider.resolve` and the guard are strictly blocking. Javalin advertises switching to async when a `Future` result is set. A provider that calls a remote IdP / JWKS endpoint / DB blocks the request thread with no first-class async option.

**Target.** Allow authentication to complete asynchronously without forcing every provider to become async and without complicating the common (blocking) case.

**Design options (to be decided in implementation plan; list trade-offs here):**
- **Option A — `CompletableFuture` result.** Add an optional async provider contract returning `CompletableFuture<AuthenticationResult>`; the guard integrates with Javalin's async support (`ctx.future { ... }`) so the request thread is released while authentication is in flight. Blocking providers remain the default and are unchanged.
- **Option B — Kotlin `suspend` provider + Java `CompletableFuture` provider.** Idiomatic for each language but larger surface and more runtime branching.
- **Recommendation:** start with **Option A** (single async abstraction, language-neutral, smallest core change). Keep synchronous `AuthenticationProvider` as the primary, zero-overhead path; async is opt-in.

**Constraints.**
- The `beforeMatched` guard must correctly suspend/resume: authorization still runs only after authentication resolves, and `skipRemainingHandlers()` / fail-closed semantics must be preserved across the async boundary.
- Virtual-thread mode (`config.useVirtualThreads`) interaction must be documented — for many users, virtual threads make blocking providers acceptable, so async is an advanced option, not the default.
- No allocation / no async machinery on the synchronous path.

**Acceptance:** a provider can perform I/O without pinning the request thread (verified by a test using Javalin's async facilities), while existing synchronous tests are unchanged.

### 4.4 CORS / `OPTIONS` preflight ergonomics (ecosystem fit)

**Problem.** With deny-by-default and typical method-scoped rules, a browser CORS preflight `OPTIONS` matches no rule → 401, silently breaking CORS.

**Target.** The extension composes with Javalin's CORS plugin without a surprising 401, while staying secure-by-default (no blanket bypass).

**Design notes (decide precisely in implementation plan):**
- Preferred: **documented recipe** + a small helper to permit preflight explicitly, e.g. a DSL convenience `permitCorsPreflight()` that adds a narrowly-scoped rule allowing `OPTIONS` requests that look like preflights (presence of `Access-Control-Request-Method`), rather than permitting all `OPTIONS` globally.
- Explicitly document ordering relative to Javalin's CORS plugin.
- Do **not** silently exempt `OPTIONS` by default — keep it opt-in to preserve the deny-by-default guarantee, but make it a one-liner.

**Acceptance:** a documented, one-line way to make CORS work; a test with the CORS plugin + security passing preflight and still enforcing rules on the real request.

### 4.5 Guard ordering guarantee (correctness / least surprise)

**Problem.** The guard is registered from the plugin's `onStart`, which runs after the `create { }` block, so a user `beforeMatched` added inside `create { }` can execute before security and observe an unset `Authentication`. Not a bypass (security still enforces), but surprising.

**Target.** The security guard runs first among `beforeMatched` handlers, so any user handler observes the resolved `Authentication`.

**Design notes.**
- Investigate `PluginPriority.EARLY` and/or an install path that guarantees the guard is the first `beforeMatched`.
- If Javalin's handler ordering can't be guaranteed via priority alone, document the constraint clearly and provide a recommended pattern.

**Acceptance:** a test proving a user `beforeMatched` sees the populated principal; documented ordering contract.

## 5. Explicitly out of scope (for this alignment)

Called out so the implementation plan doesn't scope-creep. These are separate future initiatives, not part of "Javalin-style alignment":

- Per-scheme `AuthenticationEntryPoint` / `AccessDeniedHandler` composition (multi-scheme plugins). *(Important, but a pluggability concern, not a Javalin-fit concern.)*
- Provider chain `Failure`-vs-`NotAuthenticated` policy redesign.
- Built-in security headers / CSRF.
- OpenAPI integration (the "OpenAPI" Javalin pillar) — worth a dedicated later plan; note it here so it isn't forgotten.
- Rule-matching performance bucketing for very large rule sets.

## 6. Suggested sequencing (dependency-ordered, not effort-estimated)

1. **4.1 Inline config namespace** — foundational; establishes the primary Kotlin entry point and the single build/validate path everything else reuses.
2. **4.2 Java API** — depends on 4.1's consolidated build path; delivers the biggest "Why Javalin" gap (interoperability).
3. **4.5 Guard ordering** — small, independent, improves correctness; can land alongside 4.1.
4. **4.4 CORS/OPTIONS** — small, independent; land after 4.1 so the helper fits the new DSL.
5. **4.3 Async authentication** — largest core change; do last so it builds on a stable, consolidated config/install surface.

## 7. Cross-cutting acceptance criteria

- Every existing security test still passes unchanged (no weakening of deny-by-default, matched-template authorization, ordering-independence, fail-closed, no-leak).
- New Kotlin **and** Java samples demonstrate the same configuration built "the same way" in both languages.
- Public API surface stays minimal; new types are either Java-ergonomic front-ends or opt-in capabilities.
- No reflection, no thread-locals introduced; synchronous path keeps zero async overhead.
- Docs updated so the **primary** documented usage is the inline `config.security { }` (Kotlin) / fluent builder (Java) form.

## 8. Open questions for the implementation plan

1. Async contract: settle on Option A (`CompletableFuture`) vs Option B (`suspend` + `CompletableFuture`), including virtual-thread guidance.
2. Should `JavalinSecurityConfig` be deprecated now, or kept indefinitely as the "externalized config" option?
3. Where should Java-facing types live (same package vs a dedicated `java`/`interop` package) to keep autocomplete clean for both languages?
4. Exact CORS-preflight helper semantics (preflight-only detection vs any `OPTIONS`).
5. Naming: `config.security { }` vs `config.httpSecurity { }`; `Rules` vs `AuthorizationRules.Java` for the Java factory.
