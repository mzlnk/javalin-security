package io.github.mzlnk.javalin.security.jwt

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.net.URL
import java.util.Base64

/**
 * Describes where the key(s) used to verify a JWT's signature come from.
 *
 * This is a library-agnostic description consumed by a [JwtDecoder] adapter (e.g.
 * `NimbusJwtDecoder`) — it carries no dependency on any specific JOSE/JWT library.
 *
 * Register via `jwt { keySource = JwtKeySource.publicKey(...) }` or pass to
 * [JwtVerification.builder].
 */
sealed interface JwtKeySource {

    /** Verifies tokens using a single local public key (RSA or EC). */
    class PublicKeySource internal constructor(
        val publicKey: PublicKey,
        /** Accepted JWS algorithm names (e.g. `"RS256"`). Empty means "all algorithms matching the key type". */
        val algorithms: Set<String>,
    ) : JwtKeySource

    /** Verifies tokens using a shared HMAC secret. */
    class SecretSource internal constructor(
        val secret: ByteArray,
        val algorithm: String,
    ) : JwtKeySource

    /** Verifies tokens using keys resolved (and cached) from a remote JWKS endpoint, matched by `kid`. */
    class JwksSource internal constructor(
        val url: URL,
    ) : JwtKeySource

    companion object {

        /**
         * Verifies tokens using the given local [publicKey] (RSA or EC).
         *
         * When [algorithms] is empty (the default), all JWS algorithms matching the key type are
         * accepted: RS256/384/512 + PS256/384/512 for RSA, ES256/384/512 for EC. The token's `alg`
         * header selects the specific one; `kid` is ignored — the provided key is always used.
         */
        @JvmStatic
        @JvmOverloads
        fun publicKey(publicKey: PublicKey, algorithms: Set<String> = emptySet()): JwtKeySource =
            PublicKeySource(publicKey, algorithms)

        /**
         * Verifies tokens using a public key parsed from a PEM [string].
         *
         * Supports `-----BEGIN PUBLIC KEY-----` (X.509/PKCS#8 format) for both RSA and EC keys.
         * The key type is detected automatically.
         *
         * @throws IllegalArgumentException if the PEM string cannot be parsed or the key type is unsupported.
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
         * The file must contain an X.509/PKCS#8 public key in PEM format
         * (`-----BEGIN PUBLIC KEY-----`). Both RSA and EC keys are supported.
         *
         * @throws IllegalArgumentException if the file cannot be parsed or the key type is unsupported.
         */
        @JvmStatic
        fun pemFile(path: Path): JwtKeySource = pem(Files.readString(path))

        /**
         * Verifies tokens using an HMAC [secret] string.
         *
         * The [algorithm] defaults to `"HS256"`. Pass `"HS384"` or `"HS512"` explicitly when using
         * longer secrets. The secret is encoded as UTF-8 bytes; for binary secrets use [secretBytes].
         */
        @JvmStatic
        @JvmOverloads
        fun secret(secret: String, algorithm: String = "HS256"): JwtKeySource =
            secretBytes(secret.toByteArray(Charsets.UTF_8), algorithm)

        /**
         * Verifies tokens using raw HMAC secret [bytes].
         *
         * Useful when the secret was originally stored as bytes (e.g. Base64-decoded).
         */
        @JvmStatic
        @JvmOverloads
        fun secretBytes(bytes: ByteArray, algorithm: String = "HS256"): JwtKeySource =
            SecretSource(bytes, algorithm)

        /**
         * Verifies tokens using a remote JWKS endpoint at [url].
         *
         * The JWK set is fetched and cached automatically by the adapter. Key selection is
         * `kid`-based: the token header's `kid` is matched against the remote JWK set. Both RSA
         * and EC keys are supported.
         *
         * @param url the JWKS endpoint URL string (e.g. `https://auth.example.com/.well-known/jwks.json`)
         */
        @JvmStatic
        fun jwks(url: String): JwtKeySource = jwks(URL(url))

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
