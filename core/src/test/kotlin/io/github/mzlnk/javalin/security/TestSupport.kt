package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal
import io.javalin.http.Context
import io.javalin.http.HandlerType
import io.mockk.every
import io.mockk.mockk

/** Minimal [authentication.AuthenticatedPrincipal] used across tests. */
data class TestPrincipal(override val name: String) : AuthenticatedPrincipal

/** Creates a bare [Context] mock with [Context.method], [Context.path] and [Context.header] stubbed. */
fun mockContext(
    method: HandlerType = HandlerType.GET,
    path: String = "/",
    headers: Map<String, String> = emptyMap(),
): Context =
    mockk {
        every { method() } returns method
        every { path() } returns path
        every { header(any()) } answers { headers[firstArg()] }
    }
