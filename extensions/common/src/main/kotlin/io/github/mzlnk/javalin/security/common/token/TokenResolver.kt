package io.github.mzlnk.javalin.security.common.token

import io.javalin.http.Context

/**
 * Locates a raw token string within an incoming request.
 *
 * Implementations extract the token from a header, cookie, query parameter, or other
 * [io.javalin.http.Context] source and return it, or `null` when absent. A `null` return leaves
 * the request anonymous for authorization rules to decide. Resolvers must not throw when no token
 * is present and must not perform scheme-specific verification. Defaults to [DEFAULT]
 * ([bearerHeader]) when not configured.
 */
fun interface TokenResolver {

    /** Returns the raw token string extracted from [context], or `null` when absent. */
    fun resolve(context: Context): String?

    companion object {

        private const val BEARER_PREFIX = "bearer "

        /**
         * Extracts the token from the `Bearer` scheme of [headerName] (defaults to `Authorization`).
         *
         * Recognises `Bearer` case-insensitively. Returns `null` when the header is absent, does
         * not start with `Bearer `, or the token portion is blank. The extracted token is trimmed
         * but otherwise returned as-is.
         */
        @JvmStatic
        @JvmOverloads
        fun bearerHeader(headerName: String = "Authorization"): TokenResolver = TokenResolver { context ->
            val header = context.header(headerName) ?: return@TokenResolver null
            if (!header.lowercase().startsWith(BEARER_PREFIX)) return@TokenResolver null
            val token = header.substring(BEARER_PREFIX.length).trim()
            token.ifBlank { null }
        }

        /**
         * Extracts the token from the cookie named [name].
         *
         * The cookie value is trimmed and used as-is with no scheme prefix. Returns `null` when
         * the cookie is absent or blank.
         */
        @JvmStatic
        fun cookie(name: String): TokenResolver = TokenResolver { context ->
            context.cookie(name)?.trim()?.ifBlank { null }
        }

        /** The default resolver: [bearerHeader] with the standard `Authorization` header. */
        @JvmStatic
        val DEFAULT: TokenResolver = bearerHeader()

    }

}
