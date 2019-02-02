package com.github.nhenneaux.jersey.http2.jetty.bundle;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.jetty.connector.JettyClientProperties;
import org.glassfish.jersey.jetty.connector.JettyHttp2Connector;
import org.junit.Test;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.security.KeyStore;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServer.TlsSecurityConfiguration.getKeyStore;
import static org.junit.Assert.assertEquals;

public class JettyServerTest {
    private static final int PORT = 2223;

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

    private static AutoCloseable jerseyServer(int port, JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration, final Class<?>... serviceClasses) {
        return new JettyServer(port, tlsSecurityConfiguration, serviceClasses);
    }


    @Test(timeout = 20_000)
    public void testValidTls() throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = new JettyServer.TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1.2"
        );
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            final Response ping = getClient(port, getKeyStore("jks-password".toCharArray(), "truststore.jks"), http2ClientConfig()).path("/ping").request().head();
            assertEquals(204, ping.getStatus());
        }
    }

    @Test(timeout = 60_000)
    public void testConcurrent() throws Exception {
        testConcurrent(http2ClientConfig());
    }

    @Test(timeout = 60_000)
    public void testConcurrentHttp1() throws Exception {
        testConcurrent(new ClientConfig().property(JettyClientProperties.ENABLE_SSL_HOSTNAME_VERIFICATION, Boolean.TRUE));
    }


    private void testConcurrent(ClientConfig clientConfig) throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = new JettyServer.TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1.2"
        );
        final KeyStore truststore = getKeyStore("jks-password".toCharArray(), "truststore.jks");
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            final int nThreads = 4;
            final int iterations = 10_000;
            AtomicInteger counter = new AtomicInteger();
            final Runnable runnable = () -> {
                final WebTarget client = getClient(port, truststore, clientConfig);
                final long start = System.currentTimeMillis();
                for (int i = 0; i < iterations; i++) {
                    client.path("/ping").request().head();
                    counter.incrementAndGet();
                    if (i % 1_000 == 0) {
                        System.out.println((System.currentTimeMillis() - start) * 1.0 / Math.max(i, 1));
                    }
                }
            };
            Thread.setDefaultUncaughtExceptionHandler((t1, e) -> e.printStackTrace());
            final Set<Thread> threads = IntStream
                    .range(0, nThreads)
                    .mapToObj(i -> runnable)
                    .map(Thread::new)
                    .collect(Collectors.toSet());

            threads.forEach(Thread::start);


            for (Thread thread : threads) {
                thread.join();
            }

            assertEquals(nThreads * iterations, counter.get());

        }
    }

    @Test
    public void shouldWorkInLoop() throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = new JettyServer.TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1.2"
        );
        final KeyStore truststore = getKeyStore("jks-password".toCharArray(), "truststore.jks");
        for (int i = 0; i < 100; i++) {
            try (
                    AutoCloseable ignored = jerseyServer(port, tlsSecurityConfiguration, DummyRestService.class)
            ) {
                assertEquals(204, getClient(port, truststore, http2ClientConfig()).path("/ping").request().head().getStatus());
            }
        }
    }


}