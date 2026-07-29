# Installation

Add the **core** artifact and Javalin. Everything else — Basic Auth, JWT, custom strategies — is
optional and installed from its own page.

!!! warning "Bring your own Javalin and SLF4J"
    Core does not ship with Javalin or SLF4J. If they are missing, you will get
    `NoClassDefFoundError` at runtime.

## Core

The core module is the only dependency you always need — it provides the plugin, the rule table,
and the authentication SPI. Add it alongside Javalin and an SLF4J binding to get a working
baseline.

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

Start Javalin with a minimal security block. If it boots without `NoClassDefFoundError`, core is
wired correctly.

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

Core ships **no** concrete authentication mechanism. Pick one — each page starts with its own
install snippet:

| Extension  | For                            | Guide                                                                     |
|------------|--------------------------------|---------------------------------------------------------------------------|
| Basic Auth | HTTP Basic (RFC 7617)          | [Basic Auth](../extensions/basic-auth.md#installation)                    |
| JWT        | Verified JWTs (HTTP / WebSocket) | [JWT](../extensions/jwt/index.md#installation)                          |
| Custom     | API keys, mTLS, HMAC, sessions | [Custom authentication](../guides/custom-authentication.md)               |

## Next steps

- [Secure endpoints](secure-endpoints.md) — secure your first HTTP routes and WebSocket upgrades.
- [Access caller identity](access-caller-identity.md) — read the authenticated user in handlers.
