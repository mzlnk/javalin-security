# javalin-security

**Authentication and authorization for Javalin 7, in Java and Kotlin.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![Stable Version](https://img.shields.io/maven-central/v/io.github.mzlnk/javalin-security?label=stable)](https://central.sonatype.com/artifact/io.github.mzlnk/javalin-security)
[![Build](https://github.com/mzlnk/javalin-security/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/mzlnk/javalin-security/actions/workflows/main.yml)
[![Docs Status](https://github.com/mzlnk/javalin-security/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/mzlnk/javalin-security/actions/workflows/docs.yml)
[![codecov](https://codecov.io/gh/mzlnk/javalin-security/branch/main/graph/badge.svg)](https://codecov.io/gh/mzlnk/javalin-security)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-blue?logo=openjdk)](https://adoptium.net/)
[![Kotlin 2.4+](https://img.shields.io/badge/Kotlin-2.4%2B-blue?logo=kotlin)](https://kotlinlang.org/)
[![Javalin 7.x+](https://img.shields.io/badge/Javalin-7.x%2B-blue)](https://javalin.io/)

---

`javalin-security` is a simple and lightweight community plugin for securing Javalin applications. It
gives you a batteries-included way to add authentication and authorization to your app without
pulling in a heavyweight framework or learning a large new configuration surface — just register
the plugin inside `Javalin.create { … }` and you are ready to go. The plugin is designed to be
pluggable and extensible: authentication runs through a small `AuthenticationStrategy` interface,
so you can pick whichever mechanism fits your app — a built-in strategy, or a fully custom one.
The library is intentionally built on a small set of simple abstractions — `AuthenticationStrategy`,
`Authentication`, `Identity`, `Rule` — so the mental model stays easy to reason about, while every
extension point is open for customization.

## Install

```kotlin
dependencies {
    implementation("io.github.mzlnk:javalin-security:1.0.0")
    implementation("io.javalin:javalin:7.2.2")
    implementation("org.slf4j:slf4j-simple:2.0.16")
}
```

## Get started

```kotlin
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin

val app = Javalin.create { config ->
    config.security { security ->
        security.rules.get("/public/*", Rules.allow())
        security.rules.post("/api/*", Rules.authenticated())
        security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN))
        security.http.authentication = myAuthenticationStrategy
        security.http.fallback = Rules.deny()
    }
    config.routes.get("/public/info") { it.result("hello") }
}.start(7070)
```

## Extensions

The `core` artifact ships no concrete authentication mechanism; pick one from the extensions
below (or plug in your own strategy):

| Artifact                                       | Purpose                                     |
|------------------------------------------------|---------------------------------------------|
| `io.github.mzlnk:javalin-security-basic-auth`  | HTTP Basic Auth (RFC 7617)                  |
| `io.github.mzlnk:javalin-security-api-key`     | Static API key authentication (`X-Api-Key` by default) |
| `io.github.mzlnk:javalin-security-opaque-token` | Server-issued opaque bearer tokens (sessions, PATs) with expiry |
| `io.github.mzlnk:javalin-security-jwt`         | JWT authentication (bring your own decoder) |
| `io.github.mzlnk:javalin-security-jwt-nimbus`  | JWT decoder adapter for Nimbus              |
| `io.github.mzlnk:javalin-security-jwt-auth0`   | JWT decoder adapter for Auth0               |

## Documentation

Read the documentation at: <https://mzlnk.github.io/javalin-security/>

## Contributing

Contributions are welcome. See the [Contributing guide](docs/content/contributing.md) for the
toolchain, conventions, and how to build and test locally. The release process for maintainers
is documented in [`RELEASING.md`](RELEASING.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
