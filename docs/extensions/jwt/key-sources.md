# Key sources

`JwtKeySource` describes **where the key used to verify a JWT signature comes from**. It is a
library-agnostic descriptor consumed by whichever [decoder adapter](nimbus.md) you use, and it is
required on `jwt.keySource`.

## Factory methods

| Factory                          | Verifies with                                        | Typical use                          |
|----------------------------------|------------------------------------------------------|--------------------------------------|
| `publicKey(key, algorithms?)`    | A local `java.security.PublicKey` (RSA or EC).       | You already hold the key object.     |
| `pem(string)`                    | A public key parsed from a PEM string.               | Key pasted or configured as text.    |
| `pemFile(path)`                  | A public key loaded from a PEM file.                 | Key mounted as a file.               |
| `secret(string, algorithm?)`     | An HMAC secret string (default `HS256`).             | Symmetric-key tokens.                |
| `secretBytes(bytes, algorithm?)` | Raw HMAC secret bytes (default `HS256`).             | Binary or Base64-decoded secrets.    |
| `jwks(url)`                      | Keys from a remote JWKS endpoint, matched by `kid`.  | OIDC and third-party issuers.        |

All factories are `@JvmStatic`; the `algorithms` / `algorithm` parameters are `@JvmOverloads`, so
the short forms are available from Java too.

## JWKS (recommended for OIDC issuers)

The most common choice when tokens come from an identity provider (Auth0, Keycloak, Okta,
Google, …). The decoder fetches and **caches** the JWK set and selects the key by the token's
`kid`.

=== "Kotlin"

    ```kotlin
    jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
    ```

=== "Java"

    ```java
    jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
    ```

A `jwks(URL)` overload is available if you already hold a `java.net.URL`.

## Local public key (asymmetric)

Use this when you distribute the issuer's public key with your application.

=== "Kotlin"

    ```kotlin
    // From a PEM string:
    jwt.keySource = JwtKeySource.pem(
        """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOC...
        -----END PUBLIC KEY-----
        """.trimIndent(),
    )

    // From a PEM file:
    jwt.keySource = JwtKeySource.pemFile(Path.of("/etc/secrets/jwt-public.pem"))

    // From a PublicKey you already hold (optionally restrict algorithms):
    jwt.keySource = JwtKeySource.publicKey(rsaPublicKey, setOf("RS256"))
    ```

=== "Java"

    ```java
    // From a PEM string:
    jwt.keySource = JwtKeySource.pem("""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOC...
        -----END PUBLIC KEY-----
        """);

    // From a PEM file:
    jwt.keySource = JwtKeySource.pemFile(Path.of("/etc/secrets/jwt-public.pem"));

    // From a PublicKey you already hold (optionally restrict algorithms):
    jwt.keySource = JwtKeySource.publicKey(rsaPublicKey, Set.of("RS256"));
    ```

When `publicKey(...)` is given **no** explicit algorithms, all JWS algorithms matching the key
type are accepted: **RS256/384/512 + PS256/384/512** for RSA, **ES256/384/512** for EC. The
token's `alg` header selects the specific one.

!!! danger "PEM must be X.509 / PKCS#8"
    Both `pem(...)` and `pemFile(...)` accept only `-----BEGIN PUBLIC KEY-----` (X.509 / PKCS#8)
    for RSA and EC. **PKCS#1** RSA PEMs (`-----BEGIN RSA PUBLIC KEY-----`) are rejected with an
    `IllegalArgumentException`. Convert with:
    ```bash
    openssl rsa -pubin -in pkcs1.pem -RSAPublicKey_in -outform PEM -out pkcs8.pem
    ```

## HMAC secret (symmetric)

For tokens signed with a shared secret (`HS256` / `HS384` / `HS512`). Both sides — the signer
and this verifier — must hold the same secret.

=== "Kotlin"

    ```kotlin
    jwt.keySource = JwtKeySource.secret("super-secret-value")             // HS256 by default
    jwt.keySource = JwtKeySource.secret("super-secret-value", "HS512")    // explicit algorithm
    jwt.keySource = JwtKeySource.secretBytes(base64DecodedSecret)         // raw bytes
    ```

=== "Java"

    ```java
    jwt.keySource = JwtKeySource.secret("super-secret-value");            // HS256 by default
    jwt.keySource = JwtKeySource.secret("super-secret-value", "HS512");   // explicit algorithm
    jwt.keySource = JwtKeySource.secretBytes(base64DecodedSecret);        // raw bytes
    ```

`secret(String)` encodes the string as UTF-8; use `secretBytes(...)` when the secret is binary
or Base64-encoded.

!!! warning "HMAC secret strength"
    Use a high-entropy secret of adequate length for the algorithm (at least 256 bits for
    HS256). Never commit secrets to source — load them from configuration or a secrets manager.

## Choosing a source

| Situation                                                    | Use                             |
|--------------------------------------------------------------|---------------------------------|
| Tokens from an OIDC / OAuth provider.                        | `jwks(url)`                     |
| Verifying with a public key you ship.                        | `pem` / `pemFile` / `publicKey` |
| Issuing and verifying tokens yourself with a shared secret.  | `secret` / `secretBytes`        |

Whatever you choose, pair it with the appropriate claim checks (`issuer`, `audiences`) — see
[JWT](index.md).
