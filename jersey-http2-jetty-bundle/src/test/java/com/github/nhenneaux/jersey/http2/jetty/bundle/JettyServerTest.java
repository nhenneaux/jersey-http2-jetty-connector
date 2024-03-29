package com.github.nhenneaux.jersey.http2.jetty.bundle;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.jetty.connector.JettyClientProperties;
import org.glassfish.jersey.jetty.connector.JettyHttp2Connector;
import org.hamcrest.Matchers;
import org.jboss.weld.environment.se.Weld;
import org.jboss.weld.environment.se.WeldContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServer.TlsSecurityConfiguration.getKeyStore;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("squid:S00112")
class JettyServerTest {
    static final int PORT = 2223;
    private static final String PING = "/ping";

    private static WebTarget getClient(int port, KeyStore trustStore, ClientConfig clientConfig) {
        return ClientBuilder.newBuilder()
                .trustStore(trustStore)
                .withConfig(clientConfig)
                .build()
                .target("https://localhost:" + port);
    }

    private static ClientConfig http2ClientConfig() {
        return new ClientConfig()
                .property(JettyClientProperties.ENABLE_SSL_HOSTNAME_VERIFICATION, Boolean.TRUE)
                .connectorProvider(JettyHttp2Connector::new);
    }

    static AutoCloseable jerseyServer(int port, JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration, final Class<?>... serviceClasses) {
        return new JettyServer(port, tlsSecurityConfiguration, serviceClasses);
    }

    static WebTarget getClient(int port) {
        return getClient(port, getKeyStore("TEST==ONLY==truststore-password".toCharArray(), "truststore.p12"), http2ClientConfig());
    }

    static JettyServer.TlsSecurityConfiguration tlsConfig() {
        return new JettyServer.TlsSecurityConfiguration(
                getKeyStore("TEST==ONLY==key-store-password".toCharArray(), "keystore.p12"),
                "localhost with alternate ip",
                "TEST==ONLY==key-store-password",
                "TLSv1.2"
        );
    }

    @Test
    @Timeout(20)
    void testValidTls() throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class);
             Response ping = getClient(port).path(PING).request().head()) {
            assertEquals(204, ping.getStatus());
        }
    }

    @Test
    @Timeout(60)
    void testConcurrent() throws Exception {
        testConcurrent(http2ClientConfig());
    }

    @Test
    @Timeout(60)
    void testConcurrentHttp1() throws Exception {
        testConcurrent(new ClientConfig().property(JettyClientProperties.ENABLE_SSL_HOSTNAME_VERIFICATION, Boolean.TRUE));
    }


    private void testConcurrent(ClientConfig clientConfig) throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        final KeyStore truststore = getKeyStore("TEST==ONLY==truststore-password".toCharArray(), "truststore.p12");
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            final int nThreads = 4;
            final int iterations = 10_000;
            // Warmup

            final WebTarget webTarget = getClient(port, truststore, clientConfig).path(PING).path(PING);
            webTarget.request().head().close();

            AtomicInteger counter = new AtomicInteger();
            final Runnable runnable = () -> {
                long start = System.nanoTime();
                for (int i = 0; i < iterations; i++) {
                    try (Response response = webTarget.request().head()) {
                        final InputStream inputStream = response.readEntity(InputStream.class);
                        byte[] bytes = new byte[inputStream.available()];
                        DataInputStream dataInputStream = new DataInputStream(inputStream);
                        dataInputStream.readFully(bytes);
                        response.getStatus();
                        counter.incrementAndGet();
                        int reportEveryRequests = 1_000;
                        if (i % reportEveryRequests == 0) {
                            System.out.println(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) * 1.0 / reportEveryRequests);
                            start = System.nanoTime();
                        }
                    } catch (ProcessingException | IOException e) {
                        if (e.getMessage().contains("GOAWAY")
                                || e.getMessage().contains("Broken pipe") //  The HTTP sending process failed with error, Broken pipe
                                || e.getMessage().contains("EOF reached while reading")
                                || e.getMessage().contains(" cancelled")) {//  The HTTP sending process failed with error, Stream 673 cancelled
                            i--;
                        } else {
                            throw new IllegalStateException(e);
                        }
                    }
                }
            };
            List<Throwable> thrown = new ArrayList<>();
            Thread.setDefaultUncaughtExceptionHandler((t1, e) -> {
                thrown.add(e);
                e.printStackTrace();
            });
            final Set<Thread> threads = IntStream
                    .range(0, nThreads)
                    .mapToObj(i -> runnable)
                    .map(Thread::new)
                    .collect(Collectors.toSet());

            threads.forEach(Thread::start);


            for (Thread thread : threads) {
                thread.join();
            }
            assertThat(thrown, Matchers.empty());
            assertEquals((long) nThreads * iterations, counter.get());

        }
    }

    @Test
    void shouldWorkInLoop() throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        for (int i = 0; i < 100; i++) {
            try (
                    @SuppressWarnings("unused") WeldContainer container = new Weld().initialize();
                    AutoCloseable ignored = jerseyServer(port, tlsSecurityConfiguration, DummyRestService.class);
                    final Response head = getClient(port).path(PING).request().head();
            ) {
                assertEquals(204, head.getStatus());
            }
        }
    }


}