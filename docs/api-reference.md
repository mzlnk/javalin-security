# API reference

Full generated KDoc for every public module:

- **[Open the API reference →](https://mzlnk.github.io/javalin-security/api/)**

## Modules and entry points

| Module                          | Key entry points                                                                                                       |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `javalin-security`              | `JavalinSecurityPlugin`, `security` / `authentication` / `principal`, `Authenticator`, `AuthenticationStrategy`, `Authentication`, `Rule`, `Rules`, `Anyone`. |
| `javalin-security-jwt`          | `jwt`, `JwtConfig`, `JwtDecoder`, `JwtVerification`, `JwtKeySource`, `JwtRolesMapper`, `JwtPrincipal`, `DecodedJwt`.   |
| `javalin-security-jwt-nimbus`   | `NimbusJwtDecoder`.                                                                                                    |
| `javalin-security-jwt-auth0`    | `Auth0JwtDecoder`.                                                                                                     |
| `javalin-security-basic-auth`   | `basicAuth`, `BasicAuthConfig`, `BasicAuthenticator`, `UserLookup`, `BasicUser`, `PasswordEncoder`.                    |

## Kotlin → Java equivalents

| Kotlin                           | Java                                                                    |
|----------------------------------|-------------------------------------------------------------------------|
| `config.security { … }`          | `SecurityExtensions.security(config, …)` or `new JavalinSecurityPlugin(…)`. |
| `ctx.principal<T>()`             | `SecurityExtensions.principal(ctx, Type.class)`.                        |
| `jwt { }` / `basicAuth { }`      | `JwtSecurity.jwt(…)` / `BasicAuthSecurity.basicAuth(…)`.                |
| `NimbusJwtDecoder` / `Anyone`    | `NimbusJwtDecoder.INSTANCE` / `Anyone.INSTANCE`.                        |
| `Rules.allow()` etc.             | Static `Rules.allow()` etc.                                             |

## Build KDoc locally

```bash
./gradlew :dokkaGenerate
# output: build/dokka/html/index.html
```
