# Installation

To begin, simply add the `javalin-security` library to your project dependencies. This is all you need for the minimum setup to enable authentication and authorization features in your Javalin app.

=== "Gradle (Kotlin DSL)"

    ```kotlin
    dependencies {
        implementation("io.github.mzlnk:javalin-security:{{ versions.library }}")
        implementation("io.javalin:javalin:{{ versions.javalin }}")
        implementation("org.slf4j:slf4j-simple:{{ versions.slf4j }}")
    }
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    <dependency>
      <groupId>io.javalin</groupId>
      <artifactId>javalin</artifactId>
      <version>{{ versions.javalin }}</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-simple</artifactId>
      <version>{{ versions.slf4j }}</version>
    </dependency>
    ```

## Verify the setup

Start Javalin with a minimal security block. If it boots without errors, the library is wired correctly.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    fun main() {
        Javalin.create { config ->
            config.security { security ->
                security.http.fallback = Rules.allow()
            }
            config.routes.get("/") { it.result("ok") }
        }.start(7070)
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    void main() {
        Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security ->
                security.http.fallback = Rules.allow()));
            config.routes.get("/", ctx -> ctx.result("ok"));
        }).start(7070);
    }
    ```

## Choose an extension

The `javalin-security` library itself does not include any built-in authentication mechanism. You need to either implement your own authentication strategy, or use one of the provided extensions designed for common authentication scenarios — so you don't have to build everything from scratch. Each extension's page includes its installation snippet:

| Extension                                                                                         | For                                 |
|---------------------------------------------------------------------------------------------------|-------------------------------------|
| [Basic Auth](../extensions/basic-auth.md#installation)                                            | HTTP Basic (RFC 7617)               |
| [API Key](../extensions/api-key.md#installation)                                                  | Opaque API keys (`X-Api-Key`)       |
| [Opaque Token](../extensions/opaque-token.md#installation)                                        | Server-issued opaque bearer tokens  |
| [Session](../extensions/session.md#installation)                                                  | HTTP-session cookie auth            |
| [JWT](../extensions/jwt/index.md#installation)                                                    | Verified JWTs (HTTP / WebSocket)    |
| [Custom authentication](../guides/custom-authentication.md)                                       | mTLS, HMAC, other schemes           |

## Next steps

- [Secure endpoints](secure-endpoints.md) — secure your first HTTP routes and WebSocket upgrades.
- [Access caller identity](access-caller-identity.md) — read the authenticated user in handlers.
