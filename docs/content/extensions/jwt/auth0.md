# Auth0 decoder adapter

`javalin-security-jwt-auth0` provides `Auth0JwtDecoder`, a `JwtDecoder` backed by
[auth0 java-jwt](https://github.com/auth0/java-jwt) (v4.x) with JWKS support from
[jwks-rsa](https://github.com/auth0/jwks-rsa-java).

## Installation

Add the adapter alongside [javalin-security](../../getting-started/installation.md) and the
[JWT extension](configuration.md). The Auth0 adapter needs **two** third-party libraries:

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:{{ versions.library }}")
    implementation("io.github.mzlnk:javalin-security-jwt-auth0:{{ versions.library }}")
    implementation("com.auth0:java-jwt:4.+")
    implementation("com.auth0:jwks-rsa:0.24.+")
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-jwt</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-jwt-auth0</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    <dependency>
      <groupId>com.auth0</groupId>
      <artifactId>java-jwt</artifactId>
      <version>[4,5)</version>
    </dependency>
    <dependency>
      <groupId>com.auth0</groupId>
      <artifactId>jwks-rsa</artifactId>
      <version>[0.24,1)</version>
    </dependency>
    ```

Neither library is bundled with the adapter. Add **java-jwt 4+** and **jwks-rsa 0.24+** to your
project yourself.

## Usage

`Auth0JwtDecoder` is a stateless singleton — assign it as the `decoder`:

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.auth0.Auth0JwtDecoder

    http.authentication = jwt { jwt ->
        jwt.decoder = Auth0JwtDecoder
        jwt.keySource = JwtKeySource.jwks("https://YOUR_TENANT.auth0.com/.well-known/jwks.json")
        jwt.issuer = "https://YOUR_TENANT.auth0.com/"
        jwt.audiences = setOf("https://my-api.example.com")
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.jwt.*;
    import io.github.mzlnk.javalin.security.jwt.auth0.Auth0JwtDecoder;

    http.authentication = JwtSecurity.jwt(jwt -> {
        jwt.decoder = Auth0JwtDecoder.INSTANCE;
        jwt.keySource = JwtKeySource.jwks("https://YOUR_TENANT.auth0.com/.well-known/jwks.json");
        jwt.issuer = "https://YOUR_TENANT.auth0.com/";
        jwt.audiences = Set.of("https://my-api.example.com");
    });
    ```

## Capabilities

| Capability      | Details                                                                              |
|-----------------|--------------------------------------------------------------------------------------|
| Key sources     | Public key, PEM, HMAC secret, and JWKS — all of [`JwtKeySource`](key-sources.md).    |
| RSA algorithms  | RS256/384/512, PS256/384/512.                                                        |
| EC algorithms   | ES256/384/512.                                                                       |
| HMAC algorithms | HS256/384/512.                                                                       |
| JWKS            | Fetched and **cached** per URL via `jwks-rsa`. Key selected by the token's `kid`.    |
| Claim checks    | `iss`, `aud`, and clock skew for `exp` / `nbf` from `JwtConfig`.                     |
