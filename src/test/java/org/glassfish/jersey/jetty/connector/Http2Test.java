package org.glassfish.jersey.jetty.connector;

import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.MultiException;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.proxy.WebResourceFactory;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.jboss.weld.environment.se.Weld;
import org.jboss.weld.environment.se.WeldContainer;
import org.junit.Test;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.ClientBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Test TLS encryption between a client and a server JAX-RS.
 */
public class Http2Test {

    /**
     * Weak ciphers that must be excluded from the TLS configuration. the list comes from the RFC 7540 recommendations https://tools.ietf.org/html/rfc7540#appendix-A.
     */
    public static final List<String> WEAK_CIPHERS = Collections.unmodifiableList(Arrays.asList("TLS_NULL_WITH_NULL_NULL", "TLS_RSA_WITH_NULL_MD5", "TLS_RSA_WITH_NULL_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_RSA_WITH_IDEA_CBC_SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_DSS_WITH_DES_CBC_SHA", "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_RSA_WITH_DES_CBC_SHA", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "TLS_DH_anon_WITH_RC4_128_MD5", "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_anon_WITH_DES_CBC_SHA", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_DES_CBC_SHA", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_RC4_128_SHA", "TLS_KRB5_WITH_IDEA_CBC_SHA", "TLS_KRB5_WITH_DES_CBC_MD5", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "TLS_KRB5_WITH_RC4_128_MD5", "TLS_KRB5_WITH_IDEA_CBC_MD5", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "TLS_PSK_WITH_NULL_SHA", "TLS_DHE_PSK_WITH_NULL_SHA", "TLS_RSA_PSK_WITH_NULL_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_anon_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_NULL_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "TLS_PSK_WITH_RC4_128_SHA", "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_PSK_WITH_AES_128_CBC_SHA", "TLS_PSK_WITH_AES_256_CBC_SHA", "TLS_DHE_PSK_WITH_RC4_128_SHA", "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_PSK_WITH_RC4_128_SHA", "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_SEED_CBC_SHA", "TLS_DH_DSS_WITH_SEED_CBC_SHA", "TLS_DH_RSA_WITH_SEED_CBC_SHA", "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "TLS_DH_anon_WITH_SEED_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_GCM_SHA256", "TLS_PSK_WITH_AES_256_GCM_SHA384", "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_CBC_SHA256", "TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS_PSK_WITH_NULL_SHA256", "TLS_PSK_WITH_NULL_SHA384", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_DHE_PSK_WITH_NULL_SHA256", "TLS_DHE_PSK_WITH_NULL_SHA384", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", "TLS_RSA_PSK_WITH_NULL_SHA256", "TLS_RSA_PSK_WITH_NULL_SHA384", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_ECDH_ECDSA_WITH_NULL_SHA", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_RSA_WITH_NULL_SHA", "TLS_ECDH_RSA_WITH_RC4_128_SHA", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_NULL_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_anon_WITH_NULL_SHA", "TLS_ECDH_anon_WITH_RC4_128_SHA", "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_RC4_128_SHA", "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_NULL_SHA", "TLS_ECDHE_PSK_WITH_NULL_SHA256", "TLS_ECDHE_PSK_WITH_NULL_SHA384", "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_WITH_AES_128_CCM", "TLS_RSA_WITH_AES_256_CCM", "TLS_RSA_WITH_AES_128_CCM_8", "TLS_RSA_WITH_AES_256_CCM_8", "TLS_PSK_WITH_AES_128_CCM", "TLS_PSK_WITH_AES_256_CCM", "TLS_PSK_WITH_AES_128_CCM_8", "TLS_PSK_WITH_AES_256_CCM_8"));
    private static final int PORT = 2223;
    /**
     * Weak protocol that must be excluded from the TLS configuration.
     */
    private static final List<String> WEAK_PROTOCOLS = Collections.unmodifiableList(Arrays.asList("SSL", "SSLv2", "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1"));

    public static void main(String[] args) throws Exception {
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost",
                "aXeDUspU3AvUkaf5$a",
                "TLSv1.2"
        );
        try (AutoCloseable ignored = jerseyServer(
                PORT,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            System.in.read();
        }
    }

    private static <T> T getClient(int port, KeyStore trustStore, Class<T> clazz) {
        return getClient(port, trustStore, clazz, http2ClientConfig());
    }

    private static ClientConfig http2ClientConfig() {
        return new ClientConfig()
                .property(JettyClientProperties.ENABLE_SSL_HOSTNAME_VERIFICATION, Boolean.TRUE)
                .connectorProvider(JettyHttp2Connector::new);
    }

    private static <T> T getClient(int port, KeyStore trustStore, Class<T> clazz, ClientConfig configuration) {
        return WebResourceFactory.newResource(
                clazz,
                ClientBuilder.newBuilder()
                        .register(new JacksonJsonProvider())
                        .trustStore(trustStore)
                        .withConfig(configuration
                        )
                        .build()
                        .target("https://localhost:" + port)
        );
    }

    private static AutoCloseable jerseyServer(int port, TlsSecurityConfiguration tlsSecurityConfiguration, final Class<?>... serviceClasses) {
        return new AutoCloseable() {
            private final Server server;

            {
                this.server = new Server();
                ServerConnector http2Connector =
                        new ServerConnector(server, getConnectionFactories(tlsSecurityConfiguration));
                http2Connector.setPort(port);
                server.addConnector(http2Connector);

                ServletContextHandler context = new ServletContextHandler(server, "/*", ServletContextHandler.GZIP);

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
                if (server != null) {
                    try {
                        server.stop();
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    } finally {
                        server.destroy();
                    }
                }
            }
        };
    }

    private static KeyStore getKeyStore(char[] password, String keystoreClasspathLocation) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
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

        SslContextFactory sslContextFactory = new SslContextFactory();

        sslContextFactory.setKeyStore(tlsSecurityConfiguration.keyStore);
        sslContextFactory.setKeyManagerPassword(tlsSecurityConfiguration.certificatePassword);
        sslContextFactory.setCertAlias(tlsSecurityConfiguration.certificateAlias);

        sslContextFactory.setIncludeProtocols(tlsSecurityConfiguration.protocol);
        sslContextFactory.setProtocol(tlsSecurityConfiguration.protocol);
        sslContextFactory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");

        sslContextFactory.setExcludeProtocols(WEAK_PROTOCOLS.toArray(new String[0]));

        sslContextFactory.setExcludeCipherSuites(WEAK_CIPHERS.toArray(new String[0]));

        return new ConnectionFactory[]{
                new SslConnectionFactory(sslContextFactory, alpn.getProtocol()),
                alpn,
                h2,
                new HttpConnectionFactory(httpsConfig)};
    }

    @Test(timeout = 20_000)
    public void testValidTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1.2"
        );
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            DummyRestApi.Data hello = getClient(port, getKeyStore("jks-password".toCharArray(), "truststore.jks"), DummyRestApi.class).hello();
            assertEquals(DummyRestService.helloMessage, hello.getData());
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
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
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
                final DummyRestApi client = getClient(port, truststore, DummyRestApi.class, clientConfig);
                final long start = System.currentTimeMillis();
                for (int i = 0; i < iterations; i++) {
                    client.hello();
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
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1.2"
        );
        final KeyStore truststore = getKeyStore("jks-password".toCharArray(), "truststore.jks");
        for (int i = 0; i < 100; i++) {
            try (
                    @SuppressWarnings("unused") WeldContainer container = new Weld().initialize();
                    AutoCloseable ignored = jerseyServer(port, tlsSecurityConfiguration, DummyRestService.class)
            ) {
                assertEquals(DummyRestService.helloMessage, getClient(port, truststore, DummyRestApi.class).hello().getData());
            }
        }
    }

    @Test(timeout = 20_000)
    public void testExpiredTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "expired.jks"),
                "localhost",
                "aXeDUspU3AvUkaf5$a",
                "TLSv1.2"
        );
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            try {
                getClient(port, getKeyStore("jks-password".toCharArray(), "truststore.jks"), DummyRestApi.class).hello();
                fail();
            } catch (ProcessingException e) {
                assertEquals("java.util.concurrent.ExecutionException: org.eclipse.jetty.io.EofException", e.getMessage());
            }
        }
    }

    @Test(timeout = 2_000)
    public void testInvalidAddressTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "other.jks"),
                "other",
                "VuqEvasaFr!mA3$W2Tr",
                "TLSv1.2"
        );
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            getClient(port, getKeyStore("jks-password".toCharArray(), "truststore.jks"), DummyRestApi.class).hello();
            fail();
        } catch (ProcessingException e) {
            assertEquals("java.util.concurrent.ExecutionException: org.eclipse.jetty.io.EofException", e.getMessage());
        }
    }

    @Test
    public void testNoTrustStoreTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1.2"
        );
        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            WebResourceFactory.newResource(
                    DummyRestApi.class,
                    ClientBuilder.newBuilder()
                            .register(new JacksonJsonProvider())
                            .build()
                            .target("https://localhost:" + port)).hello();
            fail();
        } catch (ProcessingException e) {
            assertEquals("javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target", e.getMessage());
        }
    }


    @Test
    public void testWrongPasswordTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=_wrong",
                "TLSv1.2"
        );

        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            getClient(port, getKeyStore("jks-password".toCharArray(), "truststore.jks"), DummyRestApi.class).hello();
            fail();
        } catch (IllegalStateException e) {
            assertEquals("java.security.UnrecoverableKeyException: Cannot recover key", e.getMessage());
        }
    }

    @Test
    public void testDeprecatedTls() throws Exception {
        int port = PORT;
        TlsSecurityConfiguration tlsSecurityConfiguration = new TlsSecurityConfiguration(
                getKeyStore("jks-keystore-password".toCharArray(), "localhost.jks"),
                "localhost with alternate ip",
                "vXzZO7sjy3jP4U7tDlihgOaf+WLlA7/vqnqlkLZzzQo=",
                "TLSv1"
        );

        try (AutoCloseable ignored = jerseyServer(
                port,
                tlsSecurityConfiguration,
                DummyRestService.class)) {
            getClient(port, getKeyStore("jks-password".toCharArray(), "truststore.jks"), DummyRestApi.class).hello();
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
