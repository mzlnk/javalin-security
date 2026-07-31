# API reference

Full generated KDoc for every public module:

- **[Open the API reference →](https://mzlnk.github.io/javalin-security/api/)**

## Modules and entry points

| Module                          | Key entry points                                                                                                       |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `javalin-security`              | `JavalinSecurityPlugin`, `security` / `authentication` / `identity` / `identityOrNull`, `Authenticator`, `AuthenticationStrategy`, `Authentication`, `Identity`, `Rule`, `Rules`, `Anyone`. |
| `javalin-security-jwt`          | `jwt`, `JwtConfig`, `JwtDecoder`, `JwtVerification`, `JwtKeySource`, `JwtRolesMapper`, `JwtIdentityMapper`, `Jwt`, `DecodedJwt`. |
| `javalin-security-jwt-nimbus`   | `NimbusJwtDecoder`.                                                                                                    |
| `javalin-security-jwt-auth0`    | `Auth0JwtDecoder`.                                                                                                     |
| `javalin-security-basic-auth`   | `basicAuth`, `BasicAuthConfig`, `BasicAuthenticator`, `BasicUserDetails`, `UserLookup`, `PasswordEncoder`.            |
| `javalin-security-api-key`      | `apiKey`, `ApiKeyConfig`, `ApiKeyAuthenticator`, `ApiKeyDetails`, `ApiKeyLookup`, `ApiKeyResolver`.                   |
| `javalin-security-opaque-token` | `opaqueToken`, `OpaqueTokenConfig`, `OpaqueTokenAuthenticator`, `OpaqueTokenLookup`, `OpaqueTokenDetails`.             |
| `javalin-security-session`      | `session`, `SessionManager`, `HttpSessionManager`, `SessionAuthenticator`, `SessionDetails`. |


## Kotlin → Java equivalents

| Kotlin                           | Java                                                                    |
|----------------------------------|-------------------------------------------------------------------------|
| `config.security { … }`          | `SecurityExtensions.security(config, …)` or `new JavalinSecurityPlugin(…)`. |
| `ctx.identity<T>()`             | `SecurityExtensions.identity(ctx, Type.class)` (throws when anonymous). |
| `ctx.identityOrNull<T>()`       | `SecurityExtensions.identityOrNull(ctx, Type.class)`.                  |
| `jwt { }` / `basicAuth { }`      | `JwtSecurity.jwt(…)` / `BasicAuthSecurity.basicAuth(…)`.                |
| `apiKey { }` / `opaqueToken { }` | `ApiKeySecurity.apiKey(…)` / `OpaqueTokenSecurity.opaqueToken(…)`.      |
| `session { }`                    | `SessionSecurity.session(…)`.                                           |
| `NimbusJwtDecoder` / `Anyone`    | `NimbusJwtDecoder.INSTANCE` / `Anyone.INSTANCE`.                        |
| `Rules.allow()` etc.             | Static `Rules.allow()` etc.                                             |

## Build KDoc locally

```bash
./gradlew :dokkaGenerate
# output: build/dokka/html/index.html
```
