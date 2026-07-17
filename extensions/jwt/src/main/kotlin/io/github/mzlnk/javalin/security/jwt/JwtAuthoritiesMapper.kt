package io.github.mzlnk.javalin.security.jwt

/**
 * Maps a decoded JWT to the set of authorities (roles/permissions/scopes) granted to the caller.
 *
 * The resulting set is passed directly to
 * [io.github.mzlnk.javalin.security.authentication.Authentication.authenticated] and is therefore
 * the value read by authorization rules such as `hasAuthority("ADMIN")`.
 *
 * Register via `jwt { authoritiesMapper = JwtAuthoritiesMapper.fromClaim("roles") }` or supply a
 * lambda. The default (when not configured) returns an empty set.
 *
 * Custom mappers receive the fully-verified [DecodedJwt] and may read any claim:
 *
 * ```kotlin
 * jwt {
 *     decoder = myDecoder
 *     authoritiesMapper = JwtAuthoritiesMapper { token ->
 *         val dept = token.claim<String>("department") ?: return@JwtAuthoritiesMapper emptySet()
 *         setOf("DEPT_$dept")
 *     }
 * }
 * ```
 */
fun interface JwtAuthoritiesMapper {

    fun map(token: DecodedJwt): Set<String>

    companion object {

        /**
         * Returns an empty-set mapper. This is the default when no mapper is configured.
         *
         * Authorization rules that require specific authorities will never be satisfied; use this
         * only when all protected routes rely solely on `authenticated()` / `permitAll()`.
         */
        @JvmStatic
        fun noAuthorities(): JwtAuthoritiesMapper = JwtAuthoritiesMapper { emptySet() }

        /**
         * Reads authorities from a single string or list-of-strings claim named [claimName].
         *
         * - If the claim value is a `String`, it is treated as a single authority.
         * - If the claim value is a `Collection<*>`, each element's `toString()` is used.
         * - If the claim is absent or of an unrecognised type, an empty set is returned.
         *
         * Example — for a token with `"roles": ["ADMIN", "USER"]`:
         * ```kotlin
         * authoritiesMapper = JwtAuthoritiesMapper.fromClaim("roles")
         * ```
         */
        @JvmStatic
        fun fromClaim(claimName: String): JwtAuthoritiesMapper = JwtAuthoritiesMapper { token ->
            when (val value = token.claims[claimName]) {
                is String -> setOf(value)
                is Collection<*> -> value.mapNotNull { it?.toString() }.toSet()
                else -> emptySet()
            }
        }

        /**
         * Reads authorities from the space-delimited `scope` claim (OAuth 2.0 convention).
         *
         * Each scope token becomes one authority string. Absent or blank scopes produce an empty set.
         *
         * Example — for a token with `"scope": "read:orders write:orders"`:
         * ```kotlin
         * authoritiesMapper = JwtAuthoritiesMapper.fromScope()
         * // → authorities = {"read:orders", "write:orders"}
         * ```
         */
        @JvmStatic
        fun fromScope(): JwtAuthoritiesMapper = JwtAuthoritiesMapper { token ->
            val scope = token.claim<String>("scope") ?: return@JwtAuthoritiesMapper emptySet()
            scope.split(" ").filter { it.isNotBlank() }.toSet()
        }

    }

}
