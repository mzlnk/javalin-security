# Auth0 decoder adapter

`javalin-security-jwt-auth0` provides `Auth0JwtDecoder`, a `JwtDecoder` backed by
[auth0 java-jwt](https://github.com/auth0/java-jwt) (v4.x) with JWKS support from
[jwks-rsa](https://github.com/auth0/jwks-rsa-java).

## Installation

On top of [core](../../getting-started/installation.md) and the [JWT extension](index.md). The
Auth0 adapter needs **two** third-party libraries:

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:1.0.0-SNAPSHOT")
    implementation("io.github.mzlnk:javalin-security-jwt-auth0:1.0.0-SNAPSHOT")
    implementation("com.auth0:java-jwt:4.6.0")    // add it yourself
    implementation("com.auth0:jwks-rsa:0.24.1")   // add it yourself
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-jwt-auth0</artifactId>
      <version>1.0.0-SNAPSHOT</version>
    </dependency>
    <dependency>
      <groupId>com.auth0</groupId>
      <artifactId>java-jwt</artifactId>
      <version>4.6.0</version>
    </dependency>
    <dependency>
      <groupId>com.auth0</groupId>
      <artifactId>jwks-rsa</artifactId>
      <version>0.24.1</version>
    </dependency>
    ```

Neither library ships with the adapter — add both yourself at the versions the adapter was built
against (**java-jwt 4.6.0**, **jwks-rsa 0.24.1**).

## Usage

`Auth0JwtDecoder` is a stateless singleton:

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
| JWKS            | Fetched and **cached** per URL via `jwks-rsa`; key selected by the token's `kid`.    |
| Claim checks    | `iss`, `aud`, and clock skew for `exp` / `nbf` from `JwtVerification`.               |

!!! info "JWKS requires a `kid`"
    With a JWKS key source, the incoming token **must** carry a `kid` header — that is how the
    adapter selects the signing key from the set. Tokens without `kid` are rejected. (Standard
    for JWKS-based verification.)

!!! warning "PEM format"
    Local PEM keys must be **X.509 / PKCS#8** (`-----BEGIN PUBLIC KEY-----`). PKCS#1 RSA PEMs are
    **not** accepted. See [Key sources](key-sources.md).

Both adapters implement the same `JwtDecoder` SPI. Auth0-issued tokens can also be verified with
Nimbus via the same JWKS URL. See [Nimbus](nimbus.md).
