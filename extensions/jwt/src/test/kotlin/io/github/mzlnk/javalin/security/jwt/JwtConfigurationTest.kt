package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class JwtConfigurationTest {

    private val testDecoder = JwtDecoder { token, _ -> SimpleDecodedJwt(subject = token, claims = emptyMap()) }

    private val ctx: Context = mockk { every { header("Authorization") } returns "Bearer some.jwt.token" }

    @Test
    fun `should throw SecurityConfigurationException when decoder is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http.authentication = jwt { jwt ->
                        jwt.keySource = JwtKeySource.secret("test-secret")
                        // decoder not set — should fail
                    }
                    security.http.fallback = Rules.allow()
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("decoder")
    }

    @Test
    fun `should throw SecurityConfigurationException when keySource is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http.authentication = jwt { jwt ->
                        jwt.decoder = testDecoder
                        // keySource not set — should fail
                    }
                    security.http.fallback = Rules.allow()
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("keySource")
    }

    @Test
    fun `should forward keySource, issuer, audiences and clockSkewSeconds to the decoder as a JwtVerification`() {
        val captured = slot<JwtVerification>()
        val decoder = mockk<JwtDecoder> {
            every { decode(any(), capture(captured)) } returns SimpleDecodedJwt(subject = "alice", claims = emptyMap())
        }
        val configuredKeySource = JwtKeySource.secret("test-secret")

        val strategy = jwt { jwt ->
            jwt.decoder = decoder
            jwt.keySource = configuredKeySource
            jwt.issuer = "https://issuer.example.com"
            jwt.audiences = setOf("api-a", "api-b")
            jwt.clockSkewSeconds = 30
        }
        strategy.authenticator().authenticate(ctx)

        val verification = captured.captured
        assertThat(verification.keySource).isSameAs(configuredKeySource)
        assertThat(verification.issuer).isEqualTo("https://issuer.example.com")
        assertThat(verification.audiences).containsExactlyInAnyOrder("api-a", "api-b")
        assertThat(verification.clockSkewSeconds).isEqualTo(30)
    }

    @Test
    fun `should forward default issuer, audiences and clockSkewSeconds when not configured`() {
        val captured = slot<JwtVerification>()
        val decoder = mockk<JwtDecoder> {
            every { decode(any(), capture(captured)) } returns SimpleDecodedJwt(subject = "alice", claims = emptyMap())
        }

        val strategy = jwt { jwt ->
            jwt.decoder = decoder
            jwt.keySource = JwtKeySource.secret("test-secret")
            // issuer, audiences, clockSkewSeconds left at their defaults
        }
        strategy.authenticator().authenticate(ctx)

        val verification = captured.captured
        assertThat(verification.issuer).isNull()
        assertThat(verification.audiences).isEmpty()
        assertThat(verification.clockSkewSeconds).isEqualTo(60)
    }

    private data class Principal(override val name: String) : Identity

    @Test
    fun `should map the verified token to a user-defined identity via identityMapper`() {
        val strategy = jwt { jwt ->
            jwt.decoder = testDecoder
            jwt.keySource = JwtKeySource.secret("test-secret")
            jwt.identityMapper = JwtIdentityMapper { token -> Principal(name = "user-${token.subject}") }
        }

        val result = strategy.authenticator().authenticate(ctx)

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.identity).isEqualTo(Principal(name = "user-some.jwt.token"))
    }

    @Test
    fun `should fail authentication when identityMapper returns null for a verified token`() {
        val strategy = jwt { jwt ->
            jwt.decoder = testDecoder
            jwt.keySource = JwtKeySource.secret("test-secret")
            jwt.identityMapper = JwtIdentityMapper { null }
        }

        val result = strategy.authenticator().authenticate(ctx)

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should throw SecurityConfigurationException when identityMapper and a non-default rolesMapper are both configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http.authentication = jwt { jwt ->
                        jwt.decoder = testDecoder
                        jwt.keySource = JwtKeySource.secret("test-secret")
                        jwt.identityMapper = JwtIdentityMapper { token -> Principal(name = token.subject) }
                        jwt.rolesMapper = JwtRolesMapper.fromScope { null }
                    }
                    security.http.fallback = Rules.allow()
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

}
