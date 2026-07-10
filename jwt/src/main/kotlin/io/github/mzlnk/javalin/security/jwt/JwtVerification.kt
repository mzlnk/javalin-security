package io.github.mzlnk.javalin.security.jwt

/**
 * Library-agnostic specification of how a token must be verified.
 *
 * Combines the [keySource] (where the verification key comes from) with the standard claim
 * checks (issuer, audience, clock skew). Built by the `jwt { }` DSL from its own fields, or
 * directly via [builder] for Java callers.
 *
 * A [JwtDecoder] adapter (e.g. `NimbusJwtDecoder`) receives this alongside the raw token and is
 * responsible for performing signature verification and claim checks accordingly — it holds no
 * configuration of its own.
 */
class JwtVerification internal constructor(
    val keySource: JwtKeySource,
    val issuer: String?,
    val audiences: Set<String>,
    val clockSkewSeconds: Int,
) {

    /**
     * Builder for [JwtVerification]. Obtain via [JwtVerification.builder].
     */
    class Builder(private val keySource: JwtKeySource) {

        private var issuer: String? = null
        private var audiences: Set<String> = emptySet()
        private var clockSkewSeconds: Int = 60

        /**
         * Validates that the token's `iss` claim matches [issuer].
         * Tokens with a different or absent issuer are rejected.
         */
        fun issuer(issuer: String): Builder = apply { this.issuer = issuer }

        /**
         * Validates that the token's `aud` claim contains the given [audiences].
         *
         * Pass a single value for the typical resource-server case:
         * ```kotlin
         * .audience("https://api.example.com")
         * ```
         */
        fun audience(vararg audiences: String): Builder = apply { this.audiences = audiences.toSet() }

        /**
         * Sets the maximum acceptable clock skew (in seconds) for `exp` and `nbf` validation.
         *
         * Defaults to `60`. Set to `0` to disable clock skew tolerance.
         */
        fun clockSkew(seconds: Int): Builder = apply { this.clockSkewSeconds = seconds }

        fun build(): JwtVerification = JwtVerification(
            keySource = keySource,
            issuer = issuer,
            audiences = audiences,
            clockSkewSeconds = clockSkewSeconds,
        )

    }

    companion object {

        /** Creates a [Builder] pre-loaded with the required [keySource]. */
        @JvmStatic
        fun builder(keySource: JwtKeySource): Builder = Builder(keySource)

        /** Creates a [JwtVerification] with the given [keySource] and default claim-validation settings. */
        @JvmStatic
        fun of(keySource: JwtKeySource): JwtVerification = Builder(keySource).build()

    }

}
