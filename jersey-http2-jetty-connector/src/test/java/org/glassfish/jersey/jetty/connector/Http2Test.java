package org.glassfish.jersey.jetty.connector;

import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.MultiException;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.client.proxy.WebResourceFactory;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.hamcrest.Matchers;
import org.jboss.weld.environment.se.Weld;
import org.jboss.weld.environment.se.WeldContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.ClientBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test TLS encryption between a client and a server JAX-RS.
 */
class Http2Test {

    /**
     * Weak ciphers that must be excluded from the TLS configuration. the list comes from the RFC 7540 recommendations https://tools.ietf.org/html/rfc7540#appendix-A.
     */
    static final List<String> WEAK_CIPHERS = Collections.unmodifiableList(Arrays.asList("TLS_NULL_WITH_NULL_NULL", "TLS_RSA_WITH_NULL_MD5", "TLS_RSA_WITH_NULL_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_RSA_WITH_IDEA_CBC_SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_DSS_WITH_DES_CBC_SHA", "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_RSA_WITH_DES_CBC_SHA", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "TLS_DH_anon_WITH_RC4_128_MD5", "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_anon_WITH_DES_CBC_SHA", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_DES_CBC_SHA", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_RC4_128_SHA", "TLS_KRB5_WITH_IDEA_CBC_SHA", "TLS_KRB5_WITH_DES_CBC_MD5", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "TLS_KRB5_WITH_RC4_128_MD5", "TLS_KRB5_WITH_IDEA_CBC_MD5", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "TLS_PSK_WITH_NULL_SHA", "TLS_DHE_PSK_WITH_NULL_SHA", "TLS_RSA_PSK_WITH_NULL_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_anon_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_NULL_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "TLS_PSK_WITH_RC4_128_SHA", "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_PSK_WITH_AES_128_CBC_SHA", "TLS_PSK_WITH_AES_256_CBC_SHA", "TLS_DHE_PSK_WITH_RC4_128_SHA", "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_PSK_WITH_RC4_128_SHA", "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_SEED_CBC_SHA", "TLS_DH_DSS_WITH_SEED_CBC_SHA", "TLS_DH_RSA_WITH_SEED_CBC_SHA", "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "TLS_DH_anon_WITH_SEED_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_GCM_SHA256", "TLS_PSK_WITH_AES_256_GCM_SHA384", "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_CBC_SHA256", "TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS_PSK_WITH_NULL_SHA256", "TLS_PSK_WITH_NULL_SHA384", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_DHE_PSK_WITH_NULL_SHA256", "TLS_DHE_PSK_WITH_NULL_SHA384", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", "TLS_RSA_PSK_WITH_NULL_SHA256", "TLS_RSA_PSK_WITH_NULL_SHA384", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_ECDH_ECDSA_WITH_NULL_SHA", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_RSA_WITH_NULL_SHA", "TLS_ECDH_RSA_WITH_RC4_128_SHA", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_NULL_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_anon_WITH_NULL_SHA", "TLS_ECDH_anon_WITH_RC4_128_SHA", "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_RC4_128_SHA", "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_NULL_SHA", "TLS_ECDHE_PSK_WITH_NULL_SHA256", "TLS_ECDHE_PSK_WITH_NULL_SHA384", "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_WITH_AES_128_CCM", "TLS_RSA_WITH_AES_256_CCM", "TLS_RSA_WITH_AES_128_CCM_8", "TLS_RSA_WITH_AES_256_CCM_8", "TLS_PSK_WITH_AES_128_CCM", "TLS_PSK_WITH_AES_256_CCM", "TLS_PSK_WITH_AES_128_CCM_8", "TLS_PSK_WITH_AES_256_CCM_8"));
    private static final int PORT = 2223;
    /**
     * Weak protocol that must be excluded from the TLS configuration.
     */
    private static final List<String> WEAK_PROTOCOLS = Collections.unmodifiableList(Arrays.asList("SSL", "SSLv2", "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1"));

    private static DummyRestApi getClient(int port, KeyStore trustStore) {
        return getClient(port, trustStore, http2ClientConfig());
    }

    private static ClientConfig http2ClientConfig() {
        return new ClientConfig()
                .connectorProvider(JettyHttp2Connector::new);
    }

    private static DummyRestApi getClient(int port, KeyStore trustStore, ClientConfig configuration) {
        return WebResourceFactory.newResource(
                DummyRestApi.class,
                ClientBuilder.newBuilder()
                        .register(new JacksonJsonProvider())
                        .trustStore(trustStore)
                        .withConfig(configuration)
                        .build()
                        .target("https://localhost:" + port)
        );
    }

    private static AutoCloseable jerseyServer(int port, TlsSecurityConfiguration tlsSecurityConfiguration, final Class<?>... serviceClasses) {
        return new AutoCloseable() {
            private final Server server;

            {
                this.server = new Server();
                ServerConnector http2Connector = new ServerConnector(server, getConnectionFactories(tlsSecurityConfiguration));
                http2Connector.setPort(port);
                server.addConnector(http2Connector);

                ServletContextHandler context = new ServletContextHandler(server, "/");

                ServletHolder servlet = new ServletHolder(new ServletContainer(new ResourceConfig() {
                    {
                        for (Class<?> serviceClass : serviceClasses) {
                            register(serviceClass);
                        }
                    }
                }));

                context.addServlet(servlet, "/*");

                try {
                    server.start();

                } catch (Exception e) {
                    try {
                        close();
                    } catch (RuntimeException closeException) {
                        MultiException multiException = new MultiException();
                        multiException.add(e);
                        multiException.add(closeException);
                        throw new IllegalStateException(multiException);
                    }
                    throw new IllegalStateException(e);
                }
            }

            @Override
            public void close() {
                try {
                    server.stop();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                } finally {
                    server.destroy();
                }
            }
        };
    }

    private static KeyStore getKeyStore(char[] password, String keystoreClasspathLocation) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(keystoreClasspathLocation.endsWith("p12") ? "PKCS12" : "JKS");
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
        try (InputStream myKeys = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystoreClasspathLocation)) {
            keystore.load(myKeys, password);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new IllegalStateException(e);
        }
        return keystore;
    }

    private static ConnectionFactory[] getConnectionFactories(TlsSecurityConfiguration tlsSecurityConfiguration) {
        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(httpsConfig);

        ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
        // Default protocol to HTTP/1.1 for compatibility with HTTP/1.1 client
        alpn.setDefaultProtocol(HttpVersion.HTTP_1_1.asString());

        SslContextFactory sslContextFactory = new SslContextFactory.Server();

        sslContextFactory.setKeyStore(tlsSecurityConfiguration.keyStore);
        sslContextFactory.setKeyManagerPassword(tlsSecurityConfiguration.certificatePassword);
        sslContextFactory.setCertAlias(tlsSecurityConfiguration.certificateAlias);

        sslContextFactory.setIncludeProtocols(tlsSecurityConfiguration.protocol);
        sslContextFactory.setProtocol(tlsSecurityConfiguration.protocol);
        sslContextFactory.setIncludeCipherSuites(
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_AES_128_CCM_8_SHA256",//TLSv1.3
                "TLS_AES_128_CCM_SHA256",//TLSv1.3
                "TLS_AES_128_GCM_SHA256",//TLSv1.3
                "TLS_AES_256_GCM_SHA384",//TLSv1.3
                "TLS_CHACHA20_POLY1305_SHA256"//TLSv1.3
        );

        sslContextFactory.setExcludeProtocols(WEAK_PROTOCOLS.toArray(new String[0]));

        sslContextFactory.setExcludeCipherSuites(WEAK_CIPHERS.toArray(new String[0]));

        return new ConnectionFactory[]{
                new SslConnectionFactory(sslContextFactory, alpn.getProtocol()),
                alpn,
                h2,
                new HttpConnectionFactory(httpsConfig)};
    }

    @Test
    @Timeout(20)
    void testValidTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            DummyRestApi.Data hello = getClient(port, getTrustStore()).hello();
            assertEquals(DummyRestService.helloMessage, hello.getData());
        }
    }

    private TlsSecurityConfiguration tlsConfig() {
        return new TlsSecurityConfiguration(
                getKeyStore("TEST==ONLY==key-store-password".toCharArray(), "keystore.p12"),
                "localhost with alternate ip",
                "TEST==ONLY==key-store-password",
                "TLSv1.2"
        );
    }

    @Test
    @Timeout(60)
    void testConcurrent() throws Exception {
        testConcurrent(http2ClientConfig());
    }

    @Test
    @Timeout(120)
    void testConcurrentJettyHttp1() throws Exception {
        testConcurrent(new ClientConfig()
                .connectorProvider(new JettyConnectorProvider()));
    }

    @Test
    @Timeout(120)
    void testConcurrentHttpUrlConnectionHttp1() throws Exception {
        testConcurrent(new ClientConfig()
                .connectorProvider(new HttpUrlConnectorProvider()));
    }
    private void testConcurrent(ClientConfig clientConfig) throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        final KeyStore truststore = getTrustStore();
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            final int nThreads = 4;
            final int iterations = 10_000;
            // Warmup
            final DummyRestApi client = getClient(port, truststore, clientConfig);
            client.hello();

            AtomicInteger counter = new AtomicInteger();
            final Runnable runnable = () -> {
                long start = System.nanoTime();
                for (int i = 0; i < iterations; i++) {
                    client.hello();
                    counter.incrementAndGet();
                    int reportEveryRequests = 1_000;
                    if (i % reportEveryRequests == 0) {
                        System.out.println(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) * 1.0 / reportEveryRequests);
                        start = System.nanoTime();
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
        TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        final KeyStore truststore = getTrustStore();
        for (int i = 0; i < 100; i++) {
            try (
                    @SuppressWarnings("unused") WeldContainer container = new Weld().initialize();
                    AutoCloseable ignored = jerseyServer(port, tlsSecurityConfiguration, DummyRestService.class)
            ) {
                assertEquals(DummyRestService.helloMessage, getClient(port, truststore).hello().getData());
            }
        }
    }

    @Test

    @Timeout(20)
    void testExpiredTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "expired.jks"),
                "localhost",
                "aXeDUspU3AvUkaf5$a",
                "TLSv1.2"
        );
        DummyRestApi client = getClient(port, getTrustStore());
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            try {
                client.hello();
                fail();
            } catch (ProcessingException expected) {
                assertThat(expected.getMessage(), anyOf(
                        equalTo("java.util.concurrent.ExecutionException: java.io.IOException: Broken pipe"),
                        equalTo("java.util.concurrent.ExecutionException: org.eclipse.jetty.io.EofException"),
                        equalTo("java.util.concurrent.ExecutionException: org.eclipse.jetty.io.RuntimeIOException: javax.net.ssl.SSLHandshakeException: General SSLEngine problem"),
                        equalTo("java.util.concurrent.ExecutionException: javax.net.ssl.SSLHandshakeException: General SSLEngine problem"),
                        equalTo("java.util.concurrent.ExecutionException: javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"),
                        equalTo("java.util.concurrent.ExecutionException: javax.net.ssl.SSLHandshakeException: (certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target")
                ));
            }
        }
    }

    @Test
    @Timeout(10)
    void testInvalidAddressTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "other.jks"),
                "other",
                "VuqEvasaFr!mA3$W2Tr",
                "TLSv1.2"
        );
        DummyRestApi client = getClient(port, getTrustStore());
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            client.hello();
            fail();
        } catch (ProcessingException expected) {
            assertThat(expected.getMessage(), anyOf(
                    equalTo("java.util.concurrent.ExecutionException: java.io.IOException: Broken pipe"),
                    equalTo("java.util.concurrent.ExecutionException: org.eclipse.jetty.io.EofException"),
                    equalTo("java.util.concurrent.ExecutionException: javax.net.ssl.SSLHandshakeException: General SSLEngine problem"),
                    equalTo("java.util.concurrent.ExecutionException: javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"),
                    equalTo("java.util.concurrent.ExecutionException: javax.net.ssl.SSLHandshakeException: (certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target")
                    )
            );
        }
    }

    @Test
    void testNoTrustStoreTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = tlsConfig();
        DummyRestApi dummyRestApi = WebResourceFactory.newResource(
                DummyRestApi.class,
                ClientBuilder.newBuilder()
                        .register(new JacksonJsonProvider())
                        .build()
                        .target("https://localhost:" + port));
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            dummyRestApi.hello();
            fail();
        } catch (ProcessingException e) {
            assertThat(e.getMessage(), containsString("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"));
        }
    }


    @Test
    void testWrongPasswordTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("TEST==ONLY==key-store-password".toCharArray(), "keystore.p12"),
                "server",
                "TEST==ONLY==key-store-password_wrong",
                "TLSv1.2"
        );

        DummyRestApi client = getClient(port, getTrustStore());
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            client.hello();
            fail();
        } catch (IllegalStateException e) {
            assertEquals("java.security.UnrecoverableKeyException: Get Key failed: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.", e.getMessage());
        }
    }

    private KeyStore getTrustStore() {
        return getKeyStore("TEST==ONLY==truststore-password".toCharArray(), "truststore.p12");
    }

    @Test
    void testDeprecatedTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("TEST==ONLY==key-store-password".toCharArray(), "keystore.p12"),
                "server",
                "TEST==ONLY==key-store-password",
                "TLSv1"
        );

        DummyRestApi client = getClient(port, getTrustStore());
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            client.hello();
            fail();
        } catch (ProcessingException ignored) {
        }
    }

    private static class TlsSecurityConfiguration {
        private final KeyStore keyStore;
        private final String certificateAlias;
        private final String certificatePassword;
        private final String protocol;

        private TlsSecurityConfiguration(KeyStore keyStore, String certificateAlias, String certificatePassword, String protocol) {
            this.keyStore = keyStore;
            this.certificateAlias = certificateAlias;
            this.certificatePassword = certificatePassword;
            this.protocol = protocol;
        }
    }
}
