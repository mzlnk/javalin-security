package io.github.mzlnk.javalin.security.jwt

import io.javalin.security.RouteRole

/**
 * Maps a decoded JWT to the set of [RouteRole]s granted to the caller.
 *
 * The resulting set is passed to
 * [io.github.mzlnk.javalin.security.authentication.Authentication.authenticated] and is used by
 * declared-role routes and authorization rules such as `hasRole`. Register via the `jwt { }` block
 * (`rolesMapper`); the default when unset is [noRoles]. Custom mappers receive a verified
 * [DecodedJwt] and may read any claim.
 */
fun interface JwtRolesMapper {

    /** Returns the [RouteRole]s granted for the given verified [token]. */
    fun map(token: DecodedJwt): Set<RouteRole>

    companion object {

        private val NO_ROLES: JwtRolesMapper = JwtRolesMapper { emptySet() }

        /**
         * Returns a mapper that always yields an empty set.
         *
         * This is the default when no mapper is configured. Authorization rules that require
         * specific roles will never match; use only when protected routes rely solely on
         * `authenticated` / `allow`. Always returns the same instance, so `jwt.rolesMapper` can be
         * compared against it to detect whether a caller configured a non-default mapper.
         */
        @JvmStatic
        fun noRoles(): JwtRolesMapper = NO_ROLES

        /**
         * Reads roles from a string or list-of-strings claim named [claimName], converting each
         * value to a [RouteRole] via [roleOf].
         *
         * A `String` claim is treated as a single role name; a `Collection<*>` uses each element's
         * `toString()`. An absent or unrecognized claim yields an empty set. Names for which
         * [roleOf] returns `null` are dropped.
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
         * Reads roles from the space-delimited `scope` claim (OAuth 2.0), converting each scope
         * token to a [RouteRole] via [roleOf].
         *
         * Absent or blank scopes yield an empty set. Scopes for which [roleOf] returns `null` are
         * dropped.
         */
        @JvmStatic
        fun fromScope(roleOf: (String) -> RouteRole?): JwtRolesMapper = JwtRolesMapper { token ->
            val scope = token.claim<String>("scope") ?: return@JwtRolesMapper emptySet()
            scope.split(" ").filter { it.isNotBlank() }.mapNotNull(roleOf).toSet()
        }

    }

}
