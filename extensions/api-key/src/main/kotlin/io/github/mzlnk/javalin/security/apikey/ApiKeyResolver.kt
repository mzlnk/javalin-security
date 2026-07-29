package io.github.mzlnk.javalin.security.apikey

import io.javalin.http.Context

/**
 * Locates a raw API key string within an incoming request.
 *
 * Implementations extract the key from a header, query parameter, cookie, or other
 * [io.javalin.http.Context] source and return it, or `null` when absent. A `null` return leaves
 * the request anonymous for authorization rules to decide. Resolvers must not throw when no key
 * is present and must not perform key validation. Defaults to [DEFAULT] ([header] with
 * `X-Api-Key`) when not configured.
 */
fun interface ApiKeyResolver {

    /** Returns the raw API key extracted from [context], or `null` when absent. */
    fun resolve(context: Context): String?

    companion object {

        /**
         * Extracts the API key from [headerName] (defaults to `X-Api-Key`).
         *
         * The header value is trimmed and used as-is. Returns `null` when the header is absent or
         * blank.
         */
        @JvmStatic
        @JvmOverloads
        fun header(headerName: String = "X-Api-Key"): ApiKeyResolver = ApiKeyResolver { context ->
            context.header(headerName)?.trim()?.ifBlank { null }
        }

        /**
         * Extracts the API key from the query parameter named [paramName].
         *
         * The parameter value is trimmed and used as-is. Returns `null` when the parameter is
         * absent or blank.
         *
         * Prefer [header] in production: query parameters commonly appear in access logs, browser
         * history, and Referer headers.
         */
        @JvmStatic
        fun query(paramName: String): ApiKeyResolver = ApiKeyResolver { context ->
            context.queryParam(paramName)?.trim()?.ifBlank { null }
        }

        /**
         * Extracts the API key from the cookie named [name].
         *
         * The cookie value is trimmed and used as-is. Returns `null` when the cookie is absent or
         * blank.
         */
        @JvmStatic
        fun cookie(name: String): ApiKeyResolver = ApiKeyResolver { context ->
            context.cookie(name)?.trim()?.ifBlank { null }
        }

        /** The default resolver: [header] with the standard `X-Api-Key` header. */
        @JvmStatic
        val DEFAULT: ApiKeyResolver = header()

    }

}
