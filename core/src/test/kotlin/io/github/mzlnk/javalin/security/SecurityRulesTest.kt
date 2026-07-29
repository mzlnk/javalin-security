package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder
import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.delete
import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.get
import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.path
import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.post
import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.ws
import io.github.mzlnk.javalin.security.authorization.Rules
import io.javalin.config.JavalinState
import io.javalin.http.HandlerType
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class SecurityRulesTest {

    @Test
    fun `verb methods should produce HTTP entries with the correct method`() {
        val rules = SecurityRules()
        rules.get("/a", Rules.allow())
        rules.post("/b", Rules.authenticated())
        rules.put("/c", Rules.deny())
        rules.patch("/d", Rules.allow())
        rules.delete("/e", Rules.deny())
        rules.head("/f", Rules.allow())
        rules.options("/g", Rules.deny())

        val http = rules.httpEntries()
        assertThat(http).hasSize(7)
        assertThat(http.map { it.method to it.pattern }).containsExactly(
            HandlerType.GET to "/a",
            HandlerType.POST to "/b",
            HandlerType.PUT to "/c",
            HandlerType.PATCH to "/d",
            HandlerType.DELETE to "/e",
            HandlerType.HEAD to "/f",
            HandlerType.OPTIONS to "/g",
        )
        assertThat(rules.wsEntries()).isEmpty()
    }

    @Test
    fun `any should produce an HTTP entry with null method`() {
        val rules = SecurityRules()
        rules.any("/any", Rules.authenticated())

        val entry = rules.httpEntries().single()
        assertThat(entry.pattern).isEqualTo("/any")
        assertThat(entry.method).isNull()
    }

    @Test
    fun `ws should produce a WebSocket entry`() {
        val rules = SecurityRules()
        rules.ws("/ws/chat", Rules.authenticated())

        assertThat(rules.httpEntries()).isEmpty()
        val entry = rules.wsEntries().single()
        assertThat(entry.pattern).isEqualTo("/ws/chat")
    }

    @Test
    fun `apiBuilder should nest and normalize path prefixes`() {
        val rules = SecurityRules()
        rules.apiBuilder {
            path("/a") {
                path("b") {
                    get("/c", Rules.allow())
                    post("d", Rules.authenticated())
                }
                delete("/*", Rules.deny())
            }
            ws("/events", Rules.authenticated())
        }

        assertThat(rules.httpEntries().map { it.method to it.pattern }).containsExactly(
            HandlerType.GET to "/a/b/c",
            HandlerType.POST to "/a/b/d",
            HandlerType.DELETE to "/a/*",
        )
        assertThat(rules.wsEntries().map { it.pattern }).containsExactly("/events")
    }

    @Test
    fun `apiBuilder should leave star path segment unprefixed with slash`() {
        val rules = SecurityRules()
        rules.apiBuilder {
            path("/api") {
                get("*", Rules.allow())
            }
        }
        assertThat(rules.httpEntries().single().pattern).isEqualTo("/api*")
    }

    @Test
    fun `static SecurityApiBuilder methods should throw outside apiBuilder`() {
        assertThatThrownBy { SecurityApiBuilder.get("/x", Rules.allow()) }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("apiBuilder")
    }

    @Test
    fun `plugin should always install both HTTP and WS guards`() {
        val state = JavalinState()
        JavalinSecurityPlugin { }.onStart(state)

        val methods = state.internalRouter.allHttpHandlers().map { it.endpoint.method }.toSet()
        assertThat(methods).contains(HandlerType.BEFORE_MATCHED, HandlerType.WEBSOCKET_BEFORE_UPGRADE)
    }

    @Test
    fun `plugin should install both guards even when only one channel has rules`() {
        val httpOnly = JavalinState()
        JavalinSecurityPlugin { security ->
            security.rules.get("/api", Rules.allow())
        }.onStart(httpOnly)

        val wsOnly = JavalinState()
        JavalinSecurityPlugin { security ->
            security.rules.ws("/ws", Rules.authenticated())
        }.onStart(wsOnly)

        assertThat(httpOnly.internalRouter.allHttpHandlers().map { it.endpoint.method }.toSet())
            .contains(HandlerType.BEFORE_MATCHED, HandlerType.WEBSOCKET_BEFORE_UPGRADE)
        assertThat(wsOnly.internalRouter.allHttpHandlers().map { it.endpoint.method }.toSet())
            .contains(HandlerType.BEFORE_MATCHED, HandlerType.WEBSOCKET_BEFORE_UPGRADE)
    }

}
