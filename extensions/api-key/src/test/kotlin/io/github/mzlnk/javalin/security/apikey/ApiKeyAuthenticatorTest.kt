package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ApiKeyAuthenticatorTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private val orders = ApiKeyPrincipal(name = "orders-svc", roles = setOf(Role.USER, Role.ADMIN))

    private val apiKeyLookup = ApiKeyLookup { rawKey -> if (rawKey == "k-valid") orders else null }

    @Test
    fun `should return NotAuthenticated when X-Api-Key header is absent`() {
        val authenticator = ApiKeyAuthenticator.of(apiKeyLookup)
        val result = authenticator.authenticate(ctx(null))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return NotAuthenticated when X-Api-Key header is blank`() {
        val authenticator = ApiKeyAuthenticator.of(apiKeyLookup)
        val result = authenticator.authenticate(ctx("   "))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return Failure when api key is unknown`() {
        val authenticator = ApiKeyAuthenticator.of(apiKeyLookup)
        val result = authenticator.authenticate(ctx("k-unknown"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Success with ApiKeyIdentity when api key is valid`() {
        val authenticator = ApiKeyAuthenticator.of(apiKeyLookup)
        val result = authenticator.authenticate(ctx("k-valid"))

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.isAuthenticated).isTrue()
        assertThat(success.authentication.identity).isInstanceOf(ApiKeyIdentity::class.java)

        val identity = success.authentication.identity as ApiKeyIdentity
        assertThat(identity.name).isEqualTo("orders-svc")
    }

    @Test
    fun `should populate roles from the looked-up principal`() {
        val authenticator = ApiKeyAuthenticator.of(apiKeyLookup)
        val result = authenticator.authenticate(ctx("k-valid")) as AuthenticationResult.Success

        assertThat(result.authentication.roles).containsExactlyInAnyOrder(Role.USER, Role.ADMIN)
    }

    @Test
    fun `should return empty roles when the looked-up principal has none`() {
        val noRolesLookup = ApiKeyLookup { rawKey ->
            if (rawKey == "k-noroles") ApiKeyPrincipal(name = "anon-svc") else null
        }
        val authenticator = ApiKeyAuthenticator.of(noRolesLookup)
        val result = authenticator.authenticate(ctx("k-noroles")) as AuthenticationResult.Success

        assertThat(result.authentication.roles).isEmpty()
    }

    @Test
    fun `builder produces a functional authenticator`() {
        val authenticator = ApiKeyAuthenticator.builder(apiKeyLookup)
            .resolver(ApiKeyResolver.DEFAULT)
            .build()

        val result = authenticator.authenticate(ctx("k-valid"))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should authenticate from a custom header when a custom resolver is configured`() {
        val authenticator = ApiKeyAuthenticator.builder(apiKeyLookup)
            .resolver(ApiKeyResolver.header("X-App-Key"))
            .build()

        val customCtx: Context = mockk {
            every { header("X-App-Key") } returns "k-valid"
        }

        val result = authenticator.authenticate(customCtx)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should return NotAuthenticated when custom header resolver finds no header`() {
        val authenticator = ApiKeyAuthenticator.builder(apiKeyLookup)
            .resolver(ApiKeyResolver.header("X-App-Key"))
            .build()

        val customCtx: Context = mockk {
            every { header("X-App-Key") } returns null
        }

        val result = authenticator.authenticate(customCtx)
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should authenticate from a query parameter when a query resolver is configured`() {
        val authenticator = ApiKeyAuthenticator.builder(apiKeyLookup)
            .resolver(ApiKeyResolver.query("api_key"))
            .build()

        val queryCtx: Context = mockk {
            every { queryParam("api_key") } returns "k-valid"
        }

        val result = authenticator.authenticate(queryCtx)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should authenticate from a cookie when a cookie resolver is configured`() {
        val authenticator = ApiKeyAuthenticator.builder(apiKeyLookup)
            .resolver(ApiKeyResolver.cookie("api_key"))
            .build()

        val cookieCtx: Context = mockk {
            every { cookie("api_key") } returns "k-valid"
        }

        val result = authenticator.authenticate(cookieCtx)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `ApiKeyIdentity name is the principal name`() {
        val identity = ApiKeyIdentity("billing-svc")
        assertThat(identity.name).isEqualTo("billing-svc")
    }

    private fun ctx(apiKeyHeader: String?): Context = mockk {
        every { header("X-Api-Key") } returns apiKeyHeader
    }
}
