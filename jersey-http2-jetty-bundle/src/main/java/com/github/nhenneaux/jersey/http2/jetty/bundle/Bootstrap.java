package com.github.nhenneaux.jersey.http2.jetty.bundle;

import java.io.IOException;

import static com.github.nhenneaux.jersey.http2.jetty.bundle.JettyServer.TlsSecurityConfiguration.getKeyStore;

public class Bootstrap {

    public static void main(String[] args) throws IOException {
        JettyServer.TlsSecurityConfiguration tlsSecurityConfiguration = new JettyServer.TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost",
                "aXeDUspU3AvUkaf5$a",
                "TLSv1.2"
        );
        try (JettyServer ignored = new JettyServer(8080, tlsSecurityConfiguration, DummyRestService.class)) {
            //noinspection ResultOfMethodCallIgnored
            System.in.read();
        }
    }
}
