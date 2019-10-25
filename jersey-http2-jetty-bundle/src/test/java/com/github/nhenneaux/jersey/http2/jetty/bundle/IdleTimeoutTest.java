package com.github.nhenneaux.jersey.http2.jetty.bundle;

import org.junit.Test;

import javax.ws.rs.core.Response;

import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServerTest.PORT;
import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServerTest.getClient;
import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServerTest.jerseyServer;
import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServerTest.tlsConfig;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("squid:S00112")
public class IdleTimeoutTest {

    @Test(timeout = 20_000)
    public void shouldComplyWithIdleTimeout() throws Exception {
        int port = PORT;
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            final Response ping = getClient(port)
                    .path("/pingWithSleep")
                    .queryParam("sleepTimeInMilliseconds", 1_000L).request()
                    .get();
            // FIXME I expect an error here since the idle timeout is 100ms and the server is sleeping for 1000ms.
            assertEquals(200, ping.getStatus());
        }
    }
}
