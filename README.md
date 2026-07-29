<div align="center">

<h1>javalin-security</h1>

<p><strong>Authentication and authorization for Javalin 7, in Java and Kotlin.</strong></p>

<!--License badge-->
<a href="LICENSE">
  <img alt="License" src="https://img.shields.io/badge/License-Apache_2.0-blue">
</a>
<!--Maven central stable version badge-->
<a href="https://central.sonatype.com/artifact/io.github.mzlnk/javalin-security">
  <img alt="Stable Version" src="https://img.shields.io/maven-central/v/io.github.mzlnk/javalin-security?label=stable">
</a>
<!--Build Status badge-->
<a href="https://github.com/mzlnk/javalin-security/actions/workflows/ci.yml">
  <img alt="Build Status" src="https://github.com/mzlnk/javalin-security/actions/workflows/ci.yml/badge.svg"/>
</a>
<!--Docs Status badge-->
<a href="https://github.com/mzlnk/javalin-security/actions/workflows/docs.yml">
  <img alt="Docs Status" src="https://github.com/mzlnk/javalin-security/actions/workflows/docs.yml/badge.svg?branch=main"/>
</a>

</div>

---

`javalin-security` is a lightweight, open-source security plugin for Javalin applications. It
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
