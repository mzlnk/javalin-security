package io.github.mzlnk.javalin.security.jwt

import io.javalin.http.Context

/**
 * Extracts the raw JWT string from the `Authorization` request header.
 *
 * Recognises the `Bearer` scheme (case-insensitive). Returns `null` when:
 * - the `Authorization` header is absent,
 * - the header value does not start with `Bearer ` (scheme token + one space),
 * - the token portion after the scheme prefix is blank.
 *
 * The extracted token is trimmed but otherwise returned as-is; no further validation is performed here.
 */
internal object BearerTokenResolver {

    private const val BEARER_PREFIX = "bearer "

    fun resolve(context: Context): String? {
        val header = context.header("Authorization") ?: return null
        if (!header.lowercase().startsWith(BEARER_PREFIX)) return null
        val token = header.substring(BEARER_PREFIX.length).trim()
        return token.ifBlank { null }
    }

}
