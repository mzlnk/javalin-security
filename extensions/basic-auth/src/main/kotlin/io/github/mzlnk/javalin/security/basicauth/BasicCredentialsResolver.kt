package io.github.mzlnk.javalin.security.basicauth

import io.javalin.http.Context
import java.util.Base64

/**
 * The single pluggable hook for locating [BasicCredentials] within an incoming request.
 *
 * Implementations decide *where* the credentials travel — by default the standard
 * `Authorization: Basic ...` header (RFC 7617) — and return the decoded [BasicCredentials], or
 * `null` when no credentials are present. A `null` return causes the request to proceed as
 * anonymous; authorization rules then decide whether access is allowed.
 *
 * Unlike the "absent" case, a *malformed* `Basic` header (invalid Base64, or a decoded value with
 * no `:` separator) is a genuine authentication failure, not an anonymous request — resolvers
 * should throw an [IllegalArgumentException] in that case so [BasicAuthAuthenticationManager] can
 * surface it as [io.github.mzlnk.javalin.security.authentication.AuthenticationResult.Failure].
 */
fun interface BasicCredentialsResolver {

    /**
     * Returns the [BasicCredentials] extracted from [context], or `null` when absent.
     *
     * @throws IllegalArgumentException when credentials are present but malformed.
     */
    fun resolve(context: Context): BasicCredentials?

    companion object {

        private const val BASIC_PREFIX = "basic "

        /**
         * Extracts credentials from the `Basic` scheme of the given [headerName] (defaults to
         * `Authorization`).
         *
         * Recognises the `Basic` scheme case-insensitively. Returns `null` when the header is
         * absent or does not start with `Basic ` (scheme token + one space). When the header does
         * carry the `Basic` scheme, the remainder is decoded as Base64 and split on the first `:`
         * into a username and password; malformed Base64 or a missing `:` separator throws an
         * [IllegalArgumentException] rather than being treated as "no credentials".
         */
        @JvmStatic
        @JvmOverloads
        fun basicHeader(headerName: String = "Authorization"): BasicCredentialsResolver = BasicCredentialsResolver { context ->
            val header = context.header(headerName) ?: return@BasicCredentialsResolver null
            if (!header.lowercase().startsWith(BASIC_PREFIX)) return@BasicCredentialsResolver null

            val encoded = header.substring(BASIC_PREFIX.length).trim()
            val decoded = try {
                Base64.getDecoder().decode(encoded).toString(Charsets.UTF_8)
            } catch (ex: IllegalArgumentException) {
                throw IllegalArgumentException("Basic credentials are not valid Base64", ex)
            }

            val separatorIndex = decoded.indexOf(':')
            if (separatorIndex < 0) {
                throw IllegalArgumentException("Basic credentials are missing the ':' separator between username and password")
            }

            BasicCredentials(
                username = decoded.substring(0, separatorIndex),
                password = decoded.substring(separatorIndex + 1),
            )
        }

        /** The default resolver: [basicHeader] with the standard `Authorization` header. */
        @JvmStatic
        val DEFAULT: BasicCredentialsResolver = basicHeader()

    }

}
