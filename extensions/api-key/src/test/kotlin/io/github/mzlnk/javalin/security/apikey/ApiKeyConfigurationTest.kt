package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class ApiKeyConfigurationTest {

    @Test
    fun `should throw SecurityConfigurationException when lookup is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http.authentication = apiKey { api ->
                        // lookup not set — should fail
                    }
                    security.http.fallback = Rules.allow()
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("lookup")
    }

}
