package io.github.mzlnk.javalin.security.jwt

/**
 * Library-agnostic specification of how a JWT must be verified.
 *
 * Combines [keySource] with standard claim checks (issuer, audience, clock skew). Built by the
 * `jwt { }` DSL or via [builder]. A [JwtDecoder] receives this alongside the raw token and
 * performs signature verification and claim checks accordingly.
 */
class JwtVerification internal constructor(
    val keySource: JwtKeySource,
    val issuer: String?,
    val audiences: Set<String>,
    val clockSkewSeconds: Int,
) {

    /** Builder for [JwtVerification]. Obtain via [JwtVerification.builder]. */
    class Builder(private val keySource: JwtKeySource) {

        private var issuer: String? = null
        private var audiences: Set<String> = emptySet()
        private var clockSkewSeconds: Int = 60

        /**
         * Requires the token's `iss` claim to match [issuer].
         *
         * Tokens with a different or absent issuer are rejected.
         */
        fun issuer(issuer: String): Builder = apply { this.issuer = issuer }

        /**
         * Requires the token's `aud` claim to contain at least one of the given [audiences].
         */
        fun audience(vararg audiences: String): Builder = apply { this.audiences = audiences.toSet() }

        /**
         * Sets the maximum acceptable clock skew in seconds for `exp` and `nbf` validation.
         *
         * Defaults to `60`. Set to `0` to disable clock-skew tolerance.
         */
        fun clockSkew(seconds: Int): Builder = apply { this.clockSkewSeconds = seconds }

        /** Builds a [JwtVerification] with the configured settings. */
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
