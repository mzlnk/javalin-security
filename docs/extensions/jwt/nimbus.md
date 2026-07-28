# Nimbus decoder adapter

`javalin-security-jwt-nimbus` provides `NimbusJwtDecoder`, a `JwtDecoder` backed by
[Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) (v10.x).

## Installation

On top of [core](../../getting-started/installation.md) and the [JWT extension](index.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:1.0.0-SNAPSHOT")
    implementation("io.github.mzlnk:javalin-security-jwt-nimbus:1.0.0-SNAPSHOT")
    implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")   // add it yourself
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-jwt-nimbus</artifactId>
      <version>1.0.0-SNAPSHOT</version>
    </dependency>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>10.9.1</version>
    </dependency>
    ```

`nimbus-jose-jwt` is not shipped with the adapter — add it yourself, ideally at the version the
adapter was built against (**10.9.1**).

## Usage

`NimbusJwtDecoder` is a stateless singleton — assign it as the `decoder`:

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder

    http.authentication = jwt { jwt ->
        jwt.decoder = NimbusJwtDecoder
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
        jwt.issuer = "https://issuer.example.com/"
        jwt.audiences = setOf("my-api")
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.jwt.*;
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;

    http.authentication = JwtSecurity.jwt(jwt -> {
        jwt.decoder = NimbusJwtDecoder.INSTANCE;
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
        jwt.issuer = "https://issuer.example.com/";
        jwt.audiences = Set.of("my-api");
    });
    ```

## Capabilities

| Capability     | Details                                                                              |
|----------------|--------------------------------------------------------------------------------------|
| Key sources    | Public key, PEM, HMAC secret, and JWKS — all of [`JwtKeySource`](key-sources.md).    |
| RSA algorithms | RS256/384/512, PS256/384/512.                                                        |
| EC algorithms  | ES256/384/512.                                                                       |
| HMAC algorithms | HS256/384/512.                                                                      |
| JWKS           | Fetched and **cached** per URL; keys selected by `kid` and key type.                 |
| Claim checks   | `iss`, `aud`, and clock skew for `exp` / `nbf` from `JwtVerification`.               |

When a public key source declares no explicit algorithms, all JWS algorithms matching the key
type are accepted (RSA → RS/PS family, EC → ES family), and the token's `alg` header selects
the specific one.

!!! warning "PEM format"
    Local PEM keys must be **X.509 / PKCS#8** (`-----BEGIN PUBLIC KEY-----`). PKCS#1 RSA PEMs
    (`-----BEGIN RSA PUBLIC KEY-----`) are **not** accepted. See [Key sources](key-sources.md).

Both Nimbus and Auth0 implement the same `JwtDecoder` SPI — pick based on which JOSE library you
prefer. See [Auth0](auth0.md).
