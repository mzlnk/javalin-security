package io.github.mzlnk.javalin.security.jwt

import io.javalin.http.Context

/**
 * The single pluggable hook for locating the raw JWT string within an incoming request.
 *
 * Implementations decide *where* the token travels — the `Authorization` header, a cookie, a
 * query parameter, or anything else derivable from the [Context] — and return the raw token
 * string, or `null` when no token is present. A `null` return causes the request to proceed as
 * anonymous ([io.github.mzlnk.javalin.security.authentication.AuthenticationResult.NotAuthenticated]);
 * authorization rules then decide whether access is allowed.
 *
 * This is deliberately separate from [JwtDecoder]: the resolver only extracts the raw string from
 * the transport (header/cookie/query param); it performs no signature verification or claim
 * checks and must never throw for the "no token present" case.
 *
 * Register via `jwt { tokenResolver = ... }` or pass to [JwtAuthenticationManager.Builder.tokenResolver].
 * Defaults to [DEFAULT] (equivalent to [bearerHeader]) when not configured.
 */
fun interface JwtTokenResolver {

    /** Returns the raw token string extracted from [context], or `null` when absent. */
    fun resolve(context: Context): String?

    companion object {

        private const val BEARER_PREFIX = "bearer "

        /**
         * Extracts the token from the `Bearer` scheme of the given [headerName] (defaults to
         * `Authorization`).
         *
         * Recognises the `Bearer` scheme case-insensitively. Returns `null` when the header is
         * absent, does not start with `Bearer ` (scheme token + one space), or the token portion
         * after the scheme prefix is blank. The extracted token is trimmed but otherwise returned
         * as-is; no further validation is performed here.
         */
        @JvmStatic
        @JvmOverloads
        fun bearerHeader(headerName: String = "Authorization"): JwtTokenResolver = JwtTokenResolver { context ->
            val header = context.header(headerName) ?: return@JwtTokenResolver null
            if (!header.lowercase().startsWith(BEARER_PREFIX)) return@JwtTokenResolver null
            val token = header.substring(BEARER_PREFIX.length).trim()
            token.ifBlank { null }
        }

        /**
         * Extracts the token from the value of the cookie named [name].
         *
         * Useful for browser/SPA flows that store the JWT in a (typically httpOnly) cookie
         * rather than sending an `Authorization` header. The cookie's raw value is trimmed and
         * used as-is — unlike [bearerHeader], no scheme prefix is expected or stripped. Returns
         * `null` when the cookie is absent or its value is blank.
         */
        @JvmStatic
        fun cookie(name: String): JwtTokenResolver = JwtTokenResolver { context ->
            context.cookie(name)?.trim()?.ifBlank { null }
        }

        /** The default resolver: [bearerHeader] with the standard `Authorization` header. */
        @JvmStatic
        val DEFAULT: JwtTokenResolver = bearerHeader()

    }

}
