package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.http.Context
import java.io.Serializable

/**
 * Default [SessionManager] backed by the servlet HTTP session.
 *
 * Stores the caller's [Identity] as a session attribute under [attributeKey]. On [create],
 * ensures a session exists and (when [rotateSessionIdOnCreate] is `true`) rotates the session
 * id via `HttpServletRequest.changeSessionId()` to defend against session fixation. On
 * [invalidate], clears the attribute and (when [invalidateSessionOnDestroy] is `true`) calls
 * `HttpSession.invalidate()`.
 *
 * [validate] never creates a session — it only reads the current session, preserving the
 * "no credentials → anonymous" contract of the extension.
 *
 * The stored [Identity] must be [Serializable] so it can travel with the session when the
 * container uses a distributed session store. [create] rejects non-serializable identities with
 * [IllegalArgumentException] — surface the failure at create time rather than at replication
 * time. Prefer enum [io.javalin.security.RouteRole]s (enums are serializable) when sessions may
 * be replicated.
 */
class HttpSessionManager private constructor(
    private val attributeKey: String,
    private val rotateSessionIdOnCreate: Boolean,
    private val invalidateSessionOnDestroy: Boolean,
) : SessionManager {

    override fun create(context: Context, identity: Identity) {
        require(identity is Serializable) {
            "HttpSessionManager requires a Serializable Identity, but ${identity::class.qualifiedName} is not. " +
                "Make your Identity type implement java.io.Serializable, or plug in a custom SessionManager."
        }
        val request = context.req()
        request.getSession(true)
        if (rotateSessionIdOnCreate) {
            request.changeSessionId()
        }
        context.sessionAttribute(attributeKey, identity)
    }

    override fun validate(context: Context): Identity? =
        context.sessionAttribute<Identity>(attributeKey)

    override fun invalidate(context: Context) {
        val session = context.req().getSession(false) ?: return
        try {
            session.removeAttribute(attributeKey)
            if (invalidateSessionOnDestroy) {
                session.invalidate()
            }
        } catch (_: IllegalStateException) {
            // Session already invalidated — nothing left to clear.
        }
    }

    /** Fluent builder for [HttpSessionManager]. */
    class Builder {

        private var attributeKey: String = DEFAULT_ATTRIBUTE_KEY
        private var rotateSessionIdOnCreate: Boolean = true
        private var invalidateSessionOnDestroy: Boolean = true

        /**
         * Overrides the session attribute name used to store the identity.
         *
         * Defaults to [DEFAULT_ATTRIBUTE_KEY].
         */
        fun attributeKey(attributeKey: String): Builder {
            this.attributeKey = attributeKey
            return this
        }

        /**
         * When `true` (default), [create] rotates the session id after ensuring a session
         * exists — session-fixation defense.
         */
        fun rotateSessionIdOnCreate(enabled: Boolean): Builder {
            this.rotateSessionIdOnCreate = enabled
            return this
        }

        /**
         * When `true` (default), [invalidate] calls `HttpSession.invalidate()` after clearing
         * the identity attribute.
         */
        fun invalidateSessionOnDestroy(enabled: Boolean): Builder {
            this.invalidateSessionOnDestroy = enabled
            return this
        }

        /** Builds an [HttpSessionManager] with the configured settings. */
        fun build(): HttpSessionManager = HttpSessionManager(
            attributeKey = attributeKey,
            rotateSessionIdOnCreate = rotateSessionIdOnCreate,
            invalidateSessionOnDestroy = invalidateSessionOnDestroy,
        )

    }

    companion object {

        /** Default session attribute key used when none is configured. */
        const val DEFAULT_ATTRIBUTE_KEY: String = "javalin-security.session.principal"

        /** Creates a [Builder] with default settings. */
        @JvmStatic
        fun builder(): Builder = Builder()

        /**
         * Creates an [HttpSessionManager] with the given [attributeKey] and default rotate /
         * invalidate behavior (both `true`).
         */
        @JvmStatic
        @JvmOverloads
        fun of(attributeKey: String = DEFAULT_ATTRIBUTE_KEY): HttpSessionManager =
            Builder().attributeKey(attributeKey).build()

    }

}
