# javalin-security

**Authentication and authorization for Javalin 7, in Java and Kotlin.**

[License](LICENSE)
[Stable Version](https://central.sonatype.com/artifact/io.github.mzlnk/javalin-security)
[Build](https://github.com/mzlnk/javalin-security/actions/workflows/main.yml)
[codecov](https://codecov.io/gh/mzlnk/javalin-security)
[Java 17+](https://adoptium.net/)
[Kotlin 2.0+](https://kotlinlang.org/)
[Javalin 7+](https://javalin.io/)

---

`javalin-security` is a lightweight and straightforward community plugin dedicated to securing Javalin applications. Its primary goal is to make adding authentication and authorization to your app as easy as possible, without dragging in large frameworks or complicated configuration. The plugin offers a clear and intuitive abstraction model, centering around interfaces like `AuthenticationStrategy`, `Authentication`, `Identity`, and `Rule`. This makes the security workflow easy to follow and understand while allowing you to customize or extend any part of the system to fit your needs.

## Get started

To get started with `javalin-security` in your Javalin project:

1. **Add the dependency** to your project's build file (example below using Gradle)

```kotlin
dependencies {
    implementation("io.github.mzlnk:javalin-security:0.1.0")
}
```

1. **Define your authentication strategy.**  You can implement the `AuthenticationStrategy` interface according to your needs, or use an existing extension (see [Extensions](#extensions) below).
2. **Configure security in your Javalin app:**
  - Add the `security` block in your Javalin configuration.
  - Define your authorization rules using `Rules` for your routes.
  - Set your authentication strategy.

Here's a minimal example in Kotlin:

```kotlin
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin

// Define your AuthenticationStrategy implementation (or use an extension)
val myAuthenticationStrategy = MyAuthenticationStrategy()

val app = Javalin.create { config ->
    config.security { security ->
        // Grant access based on rules
        security.rules.get("/public/*", Rules.allow())
        security.rules.post("/api/*", Rules.authenticated())

        // Set authentication and fallback rule
        security.http.authentication = myAuthenticationStrategy
        security.http.fallback = Rules.deny()
    }

    // Define your routes
    config.routes.get("/public/info") { ctx -> ctx.result("hello") }
}.start(7070)
```

For more usage patterns and customization options, check out the [official documentation](https://mzlnk.github.io/javalin-security/).

## Extensions

The `javalin-security` library itself does not provide any built-in authentication mechanisms - you supply your own authentication strategy as needed. However, for common use cases, there are ready-made extensions available that offer plug-and-play authentication strategies, so you do not need to create them on your own totally from scratch


| Extension                       | Description                                                     |
| ------------------------------- | --------------------------------------------------------------- |
| `javalin-security-basic-auth`   | HTTP Basic Auth (RFC 7617)                                      |
| `javalin-security-api-key`      | Static API key authentication (`X-Api-Key` by default)          |
| `javalin-security-opaque-token` | Server-issued opaque bearer tokens (sessions, PATs) with expiry |
| `javalin-security-session`      | HTTP-session authentication                                     |
| `javalin-security-jwt`          | JWT authentication                                              |




## Documentation

Read the documentation at: [https://mzlnk.github.io/javalin-security/](https://mzlnk.github.io/javalin-security/)

## Contributing

Contributions are welcome. See the [Contributing guide](docs/content/contributing.md) for the
toolchain, conventions, and how to build and test locally. The release process for maintainers
is documented in `[RELEASING.md](RELEASING.md)`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).