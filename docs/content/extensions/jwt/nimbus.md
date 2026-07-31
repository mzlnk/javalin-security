# Nimbus decoder adapter

`javalin-security-jwt-nimbus` provides `NimbusJwtDecoder`, a `JwtDecoder` backed by
[Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) (v10.x).

## Installation

Add the adapter alongside [javalin-security](../../getting-started/installation.md) and the
[JWT extension](configuration.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:{{ versions.library }}")
    implementation("io.github.mzlnk:javalin-security-jwt-nimbus:{{ versions.library }}")
    implementation("com.nimbusds:nimbus-jose-jwt:10.+")
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
      <artifactId>javalin-security-jwt-nimbus</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>[10,11)</version>
    </dependency>
    ```

`nimbus-jose-jwt` is not bundled with the adapter. Add any **10+** release of that library to
your project yourself.

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
| JWKS           | Fetched and **cached** per URL. Keys are selected by `kid` and key type.             |
| Claim checks   | `iss`, `aud`, and clock skew for `exp` / `nbf` from `JwtConfig`.                     |

When a public key source declares no explicit algorithms, all JWS algorithms matching the key
type are accepted (RSA → RS/PS family, EC → ES family), and the token's `alg` header selects
the specific one.
