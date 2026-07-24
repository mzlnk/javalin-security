package io.github.mzlnk.javalin.security.jwt

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.net.URI
import java.net.URL
import java.util.Base64

/**
 * Describes where the key(s) used to verify a JWT signature come from.
 *
 * This is a library-agnostic description consumed by a [JwtDecoder]. Register via the `jwt { }`
 * block (`keySource`) or pass to [JwtVerification.builder].
 */
sealed interface JwtKeySource {

    /** Verifies tokens using a single local public key (RSA or EC). */
    class PublicKeySource internal constructor(
        val publicKey: PublicKey,
        /** Accepted JWS algorithm names (e.g. `"RS256"`). Empty means all algorithms matching the key type. */
        val algorithms: Set<String>,
    ) : JwtKeySource

    /** Verifies tokens using a shared HMAC secret. */
    class SecretSource internal constructor(
        val secret: ByteArray,
        val algorithm: String,
    ) : JwtKeySource

    /** Verifies tokens using keys resolved from a remote JWKS endpoint, matched by `kid`. */
    class JwksSource internal constructor(
        val url: URL,
    ) : JwtKeySource

    companion object {

        /**
         * Verifies tokens using the given local [publicKey] (RSA or EC).
         *
         * When [algorithms] is empty (the default), all JWS algorithms matching the key type are
         * accepted: RS256/384/512 and PS256/384/512 for RSA, ES256/384/512 for EC. The token's
         * `alg` header selects the specific one; `kid` is ignored and the provided key is always used.
         */
        @JvmStatic
        @JvmOverloads
        fun publicKey(publicKey: PublicKey, algorithms: Set<String> = emptySet()): JwtKeySource =
            PublicKeySource(publicKey, algorithms)

        /**
         * Verifies tokens using a public key parsed from a PEM [string].
         *
         * Supports `-----BEGIN PUBLIC KEY-----` (X.509/PKCS#8) for both RSA and EC; the key type is
         * detected automatically. Throws [IllegalArgumentException] if the PEM cannot be parsed or
         * the key type is unsupported.
         */
        @JvmStatic
        fun pem(pem: String): JwtKeySource {
            val key = parsePemPublicKey(pem)
            if (key !is RSAPublicKey && key !is ECPublicKey) {
                throw IllegalArgumentException(
                    "Unsupported public key type '${key.algorithm}'; only RSA and EC are supported.",
                )
            }
            return PublicKeySource(key, emptySet())
        }

        /**
         * Verifies tokens using a public key loaded from a PEM [file].
         *
         * The file must contain an X.509/PKCS#8 public key (`-----BEGIN PUBLIC KEY-----`); RSA and
         * EC are supported. Throws [IllegalArgumentException] if the file cannot be parsed or the
         * key type is unsupported.
         */
        @JvmStatic
        fun pemFile(path: Path): JwtKeySource = pem(Files.readString(path))

        /**
         * Verifies tokens using an HMAC [secret] string.
         *
         * [algorithm] defaults to `"HS256"`; pass `"HS384"` or `"HS512"` when needed. The secret is
         * encoded as UTF-8 bytes; for binary secrets use [secretBytes].
         */
        @JvmStatic
        @JvmOverloads
        fun secret(secret: String, algorithm: String = "HS256"): JwtKeySource =
            secretBytes(secret.toByteArray(Charsets.UTF_8), algorithm)

        /**
         * Verifies tokens using raw HMAC secret [bytes].
         *
         * Use when the secret is already available as bytes (for example Base64-decoded).
         * [algorithm] defaults to `"HS256"`.
         */
        @JvmStatic
        @JvmOverloads
        fun secretBytes(bytes: ByteArray, algorithm: String = "HS256"): JwtKeySource =
            SecretSource(bytes, algorithm)

        /**
         * Verifies tokens using a remote JWKS endpoint at [url].
         *
         * The JWK set is fetched and cached by the decoder adapter. Key selection is `kid`-based;
         * RSA and EC keys are supported.
         */
        @JvmStatic
        fun jwks(url: String): JwtKeySource = jwks(URI.create(url).toURL())

        /** Verifies tokens using a remote JWKS endpoint at [url]. */
        @JvmStatic
        fun jwks(url: URL): JwtKeySource = JwksSource(url)

        private fun parsePemPublicKey(pem: String): PublicKey {
            val base64 = pem.lines()
                .filterNot { it.startsWith("-----") }
                .joinToString("")
                .replace("\\s".toRegex(), "")
            val der = Base64.getDecoder().decode(base64)
            val spec = X509EncodedKeySpec(der)
            return try {
                KeyFactory.getInstance("RSA").generatePublic(spec)
            } catch (_: InvalidKeySpecException) {
                try {
                    KeyFactory.getInstance("EC").generatePublic(spec)
                } catch (e: InvalidKeySpecException) {
                    throw IllegalArgumentException(
                        "Cannot parse PEM as RSA or EC public key. " +
                            "Only X.509/PKCS#8 format (-----BEGIN PUBLIC KEY-----) is supported.",
                        e,
                    )
                }
            }
        }

    }

}
