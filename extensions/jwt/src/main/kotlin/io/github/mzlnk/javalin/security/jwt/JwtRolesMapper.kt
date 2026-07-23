package io.github.mzlnk.javalin.security.jwt

import io.javalin.security.RouteRole

/**
 * Maps a decoded JWT to the set of [RouteRole]s granted to the caller.
 *
 * The resulting set is passed directly to
 * [io.github.mzlnk.javalin.security.authentication.Authentication.authenticated] and is therefore
 * the value read by declared-role routes/endpoints and by authorization rules such as
 * `hasRole(Role.ADMIN)`.
 *
 * Register via the `jwt { }` block (`rolesMapper` field, e.g. [fromClaim]) or supply a lambda.
 * The default (when not configured) returns an empty set.
 *
 * Custom mappers receive the fully-verified [DecodedJwt] and may read any claim:
 *
 * ```kotlin
 * jwt {
 *     decoder = myDecoder
 *     rolesMapper = JwtRolesMapper { token ->
 *         val dept = token.claim<String>("department") ?: return@JwtRolesMapper emptySet()
 *         setOf(Role.valueOf("DEPT_$dept"))
 *     }
 * }
 * ```
 */
fun interface JwtRolesMapper {

    fun map(token: DecodedJwt): Set<RouteRole>

    companion object {

        /**
         * Returns an empty-set mapper. This is the default when no mapper is configured.
         *
         * Authorization rules that require specific roles will never be satisfied; use this only
         * when all protected routes rely solely on `authenticated` / `allow`.
         */
        @JvmStatic
        fun noRoles(): JwtRolesMapper = JwtRolesMapper { emptySet() }

        /**
         * Reads roles from a single string or list-of-strings claim named [claimName], converting
         * each string value to a [RouteRole] via the app-supplied [roleOf] factory.
         *
         * - If the claim value is a `String`, it is treated as a single role name.
         * - If the claim value is a `Collection<*>`, each element's `toString()` is used.
         * - If the claim is absent or of an unrecognised type, an empty set is returned.
         * - Any name for which [roleOf] returns `null` is dropped.
         *
         * Example — for a token with `"roles": ["ADMIN", "USER"]`:
         * ```kotlin
         * rolesMapper = JwtRolesMapper.fromClaim("roles") { name -> Role.entries.find { it.name == name } }
         * ```
         */
        @JvmStatic
        fun fromClaim(claimName: String, roleOf: (String) -> RouteRole?): JwtRolesMapper = JwtRolesMapper { token ->
            val names = when (val value = token.claims[claimName]) {
                is String -> setOf(value)
                is Collection<*> -> value.mapNotNull { it?.toString() }.toSet()
                else -> emptySet()
            }
            names.mapNotNull(roleOf).toSet()
        }

        /**
         * Reads roles from the space-delimited `scope` claim (OAuth 2.0 convention), converting
         * each scope token to a [RouteRole] via the app-supplied [roleOf] factory.
         *
         * Each scope token is looked up individually. Absent or blank scopes produce an empty
         * set. Any scope for which [roleOf] returns `null` is dropped.
         *
         * Example — for a token with `"scope": "read:orders write:orders"`:
         * ```kotlin
         * rolesMapper = JwtRolesMapper.fromScope { scope -> Role.entries.find { it.scope == scope } }
         * ```
         */
        @JvmStatic
        fun fromScope(roleOf: (String) -> RouteRole?): JwtRolesMapper = JwtRolesMapper { token ->
            val scope = token.claim<String>("scope") ?: return@JwtRolesMapper emptySet()
            scope.split(" ").filter { it.isNotBlank() }.mapNotNull(roleOf).toSet()
        }

    }

}
