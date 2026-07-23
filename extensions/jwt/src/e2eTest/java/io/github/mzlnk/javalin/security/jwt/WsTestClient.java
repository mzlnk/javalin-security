package io.github.mzlnk.javalin.security.jwt;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Java-side counterpart of the WebSocket test helper duplicated across the Kotlin e2e WS test
 * classes — attempts a WebSocket upgrade and reports whether it succeeded or was rejected by the
 * security guard before the handshake completed.
 */
final class WsTestClient {

    private WsTestClient() {
    }

    /** The outcome of a WebSocket upgrade attempt. */
    record UpgradeAttempt(boolean connected, Integer statusCode) {
    }

    /**
     * Attempts a WebSocket upgrade and returns whether it connected, and — on HTTP-level
     * rejection — the server's status code (extracted from {@link WebSocketHandshakeException}).
     */
    static UpgradeAttempt tryConnect(String origin, String path, Map<String, String> headers) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean connected = new AtomicBoolean(false);
        AtomicReference<Integer> statusCode = new AtomicReference<>(null);

        URI wsUri = URI.create(origin.replace("http://", "ws://") + path);
        WebSocket.Builder builder = HttpClient.newHttpClient().newWebSocketBuilder();
        headers.forEach(builder::header);

        builder.buildAsync(wsUri, new WebSocket.Listener() {
            @Override
            public void onOpen(WebSocket webSocket) {
                connected.set(true);
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "").thenRun(latch::countDown);
            }
        }).exceptionally(t -> {
            Throwable cause = (t instanceof CompletionException && t.getCause() != null) ? t.getCause() : t;
            if (cause instanceof WebSocketHandshakeException handshakeException) {
                statusCode.set(handshakeException.getResponse().statusCode());
            }
            latch.countDown();
            return null;
        });

        awaitQuietly(latch, 3, TimeUnit.SECONDS);
        return new UpgradeAttempt(connected.get(), statusCode.get());
    }

    private static void awaitQuietly(CountDownLatch latch, long timeout, TimeUnit unit) {
        try {
            latch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
