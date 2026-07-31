# Roles mapping

A `JwtRolesMapper` turns a verified JWT into the set of `RouteRole`s granted to the caller.
Those roles land on `Authentication.roles` and drive `hasRole` / `hasAnyRole` rules and
role-declaring routes in javalin-security.

!!! danger "The default grants NO roles"
    `jwt.rolesMapper` defaults to `JwtRolesMapper.noRoles()`, which always returns an empty set.
    With it, **every role-based check fails**. Authenticated callers can only satisfy
    `authenticated` / `allow`. As soon as you use roles, configure a real mapper.

## Built-in mappers

| Mapper                       | Reads from                                         | Behavior                                       |
|------------------------------|----------------------------------------------------|------------------------------------------------|
| `noRoles()`                  | —                                                  | Always empty (the default).                    |
| `fromClaim(name, roleOf)`    | A string or list-of-strings claim.                 | Each value → a role via `roleOf`.              |
| `fromScope(roleOf)`          | The space-delimited `scope` claim (OAuth 2.0).     | Each scope token → a role via `roleOf`.        |

The `roleOf` function maps a string name to a `RouteRole?`. Returning `null` drops that name —
unknown roles are ignored rather than causing failure.

## From a claim

Use this when your issuer puts roles in a custom claim, for example `"roles": ["ADMIN", "USER"]`
or a single `"role": "ADMIN"`.

=== "Kotlin"

    ```kotlin
    enum class Role : RouteRole { ADMIN, USER }

    // Map each string in the "roles" claim to a RouteRole (null = ignore)
    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
        Role.entries.find { it.name == name }
    }
    ```

=== "Java"

    ```java
    enum Role implements RouteRole { ADMIN, USER }

    // Map each string in the "roles" claim to a RouteRole (null = ignore)
    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> {
        try { return Role.valueOf(name); }
        catch (IllegalArgumentException e) { return null; }   // drop unknown role names
    });
    ```

`fromClaim` accepts either a `String` claim (a single role) or a `Collection<*>` claim (each
element's `toString()` becomes a name). An absent or unrecognized claim yields an empty set.

## From the OAuth `scope` claim

Use this when your authorization server issues OAuth scopes, for example
`"scope": "orders:read orders:write admin"`.

=== "Kotlin"

    ```kotlin
    // Map each space-delimited scope token to a RouteRole
    jwt.rolesMapper = JwtRolesMapper.fromScope { scope ->
        when (scope) {
            "admin" -> Role.ADMIN
            "orders:write" -> Role.ORDER_WRITER
            else -> null
        }
    }
    ```

=== "Java"

    ```java
    // Map each space-delimited scope token to a RouteRole
    jwt.rolesMapper = JwtRolesMapper.fromScope(scope -> switch (scope) {
        case "admin" -> Role.ADMIN;
        case "orders:write" -> Role.ORDER_WRITER;
        default -> null;
    });
    ```

`fromScope` reads the standard `scope` claim, splits it on spaces, drops blanks, and maps each
token via `roleOf`.

## Custom mapper

`JwtRolesMapper` is a functional interface. Implement it directly for anything more complex —
nested claims, Keycloak's `realm_access.roles`, combining multiple claims, and so on.

=== "Kotlin"

    ```kotlin
    // Keycloak: roles live under realm_access.roles
    jwt.rolesMapper = JwtRolesMapper { token ->
        val realmAccess = token.claim<Map<String, Any?>>("realm_access")
        @Suppress("UNCHECKED_CAST")
        val names = (realmAccess?.get("roles") as? Collection<*>)?.mapNotNull { it?.toString() } ?: emptyList()
        names.mapNotNull { name -> Role.entries.find { it.name == name } }.toSet()
    }
    ```

=== "Java"

    ```java
    // Keycloak: roles live under realm_access.roles
    jwt.rolesMapper = token -> {
        Map<String, Object> realmAccess = token.claim("realm_access");
        if (realmAccess == null) return Set.of();
        Object roles = realmAccess.get("roles");
        if (!(roles instanceof Collection<?> c)) return Set.of();
        return c.stream()
            .map(Object::toString)
            .map(name -> { try { return (RouteRole) Role.valueOf(name); }
                           catch (IllegalArgumentException e) { return null; } })
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
    };
    ```