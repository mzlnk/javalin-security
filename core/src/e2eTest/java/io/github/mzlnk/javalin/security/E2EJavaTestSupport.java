package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler;
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler;

/**
 * Java-side counterpart of {@code E2ETestSupport.kt}'s {@code authenticationStrategy}/{@code asyncAuthenticationStrategy} —
 * building an {@link AuthenticationStrategy} directly from Java, the way a fully custom
 * authentication mechanism (not provided by a companion library's {@code jwt( )} /
 * {@code basicAuth( )} factory) is wired up.
 */
final class E2EJavaTestSupport {

    private E2EJavaTestSupport() {
    }

    static AuthenticationStrategy.Sync authenticationStrategy(Authenticator authenticator) {
        return authenticationStrategy(authenticator, UnauthorizedHandler.getDEFAULT(), ForbiddenHandler.getDEFAULT());
    }

    static AuthenticationStrategy.Sync authenticationStrategy(
            Authenticator authenticator,
            UnauthorizedHandler unauthorizedHandler,
            ForbiddenHandler forbiddenHandler
    ) {
        return new AuthenticationStrategy.Sync() {
            @Override
            public Authenticator authenticator() {
                return authenticator;
            }

            @Override
            public UnauthorizedHandler getUnauthorizedHandler() {
                return unauthorizedHandler;
            }

            @Override
            public ForbiddenHandler getForbiddenHandler() {
                return forbiddenHandler;
            }
        };
    }

    static AuthenticationStrategy.Async asyncAuthenticationStrategy(AsyncAuthenticator authenticator) {
        return asyncAuthenticationStrategy(authenticator, UnauthorizedHandler.getDEFAULT(), ForbiddenHandler.getDEFAULT());
    }

    static AuthenticationStrategy.Async asyncAuthenticationStrategy(
            AsyncAuthenticator authenticator,
            UnauthorizedHandler unauthorizedHandler,
            ForbiddenHandler forbiddenHandler
    ) {
        return new AuthenticationStrategy.Async() {
            @Override
            public AsyncAuthenticator authenticator() {
                return authenticator;
            }

            @Override
            public UnauthorizedHandler getUnauthorizedHandler() {
                return unauthorizedHandler;
            }

            @Override
            public ForbiddenHandler getForbiddenHandler() {
                return forbiddenHandler;
            }
        };
    }
}
