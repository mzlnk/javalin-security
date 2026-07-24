package io.github.mzlnk.javalin.security;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Shared WebSocket upgrade helpers for Java e2e tests. */
final class WsTestClient {

    private WsTestClient() {
    }

    /** Result of a WebSocket upgrade attempt. */
    record UpgradeAttempt(boolean connected, Integer statusCode) {
    }

    /** Attempts a WebSocket upgrade; on HTTP rejection, {@code statusCode} holds the response status. */
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

    /** Attempts a WebSocket upgrade and returns the HTTP rejection response body, if any. */
    static String upgradeRejectionBody(String origin, String path, Map<String, String> headers) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> body = new AtomicReference<>("");

        URI wsUri = URI.create(origin.replace("http://", "ws://") + path);
        WebSocket.Builder builder = HttpClient.newHttpClient().newWebSocketBuilder();
        headers.forEach(builder::header);

        builder.buildAsync(wsUri, new WebSocket.Listener() {
            @Override
            public void onOpen(WebSocket webSocket) {
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "").thenRun(latch::countDown);
            }
        }).exceptionally(t -> {
            Throwable cause = (t instanceof CompletionException && t.getCause() != null) ? t.getCause() : t;
            if (cause instanceof WebSocketHandshakeException handshakeException) {
                Object responseBody = handshakeException.getResponse().body();
                body.set(responseBody == null ? "" : responseBody.toString());
            }
            latch.countDown();
            return null;
        });

        awaitQuietly(latch, 3, TimeUnit.SECONDS);
        return body.get();
    }

    /** Sends a raw WebSocket upgrade over TCP and returns the HTTP status code from the status line. */
    static int rawUpgradeStatusCode(String host, int port, String path, Map<String, String> extraHeaders) {
        try (Socket socket = new Socket(host, port)) {
            socket.setSoTimeout(5_000);
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.ISO_8859_1));
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));

            out.write("GET " + path + " HTTP/1.1\r\n");
            out.write("Host: " + host + ":" + port + "\r\n");
            out.write("Upgrade: websocket\r\n");
            out.write("Connection: Upgrade\r\n");
            out.write("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
            out.write("Sec-WebSocket-Version: 13\r\n");
            for (Map.Entry<String, String> header : extraHeaders.entrySet()) {
                out.write(header.getKey() + ": " + header.getValue() + "\r\n");
            }
            out.write("\r\n");
            out.flush();

            String statusLine = in.readLine();
            if (statusLine == null) return -1;
            String[] parts = statusLine.split(" ");
            return parts.length > 1 ? Integer.parseInt(parts[1]) : -1;
        } catch (IOException e) {
            return -1;
        }
    }

    private static void awaitQuietly(CountDownLatch latch, long timeout, TimeUnit unit) {
        try {
            latch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
