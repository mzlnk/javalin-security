package io.github.mzlnk.javalin.security

import io.javalin.http.Context
import io.javalin.http.HandlerType
import io.mockk.every
import io.mockk.mockk

/** Minimal [AuthenticatedPrincipal] used across tests. */
data class TestPrincipal(override val name: String) : AuthenticatedPrincipal

/** Creates a bare [Context] mock with [Context.method] and [Context.path] stubbed. */
fun mockContext(method: HandlerType = HandlerType.GET, path: String = "/"): Context =
    mockk {
        every { method() } returns method
        every { path() } returns path
    }
