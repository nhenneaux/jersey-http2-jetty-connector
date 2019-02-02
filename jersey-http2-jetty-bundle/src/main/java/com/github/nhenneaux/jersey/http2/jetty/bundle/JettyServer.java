package com.github.nhenneaux.jersey.http2.jetty.bundle;

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
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class JettyServer implements AutoCloseable {

    /**
     * Weak ciphers that must be excluded from the TLS configuration. the list comes from the RFC 7540 recommendations https://tools.ietf.org/html/rfc7540#appendix-A.
     */
    private static final List<String> WEAK_CIPHERS = Collections.unmodifiableList(Arrays.asList("TLS_NULL_WITH_NULL_NULL", "TLS_RSA_WITH_NULL_MD5", "TLS_RSA_WITH_NULL_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_RSA_WITH_IDEA_CBC_SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_DSS_WITH_DES_CBC_SHA", "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_RSA_WITH_DES_CBC_SHA", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "TLS_DH_anon_WITH_RC4_128_MD5", "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_anon_WITH_DES_CBC_SHA", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_DES_CBC_SHA", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_RC4_128_SHA", "TLS_KRB5_WITH_IDEA_CBC_SHA", "TLS_KRB5_WITH_DES_CBC_MD5", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "TLS_KRB5_WITH_RC4_128_MD5", "TLS_KRB5_WITH_IDEA_CBC_MD5", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "TLS_PSK_WITH_NULL_SHA", "TLS_DHE_PSK_WITH_NULL_SHA", "TLS_RSA_PSK_WITH_NULL_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_anon_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_NULL_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "TLS_PSK_WITH_RC4_128_SHA", "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_PSK_WITH_AES_128_CBC_SHA", "TLS_PSK_WITH_AES_256_CBC_SHA", "TLS_DHE_PSK_WITH_RC4_128_SHA", "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_PSK_WITH_RC4_128_SHA", "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_SEED_CBC_SHA", "TLS_DH_DSS_WITH_SEED_CBC_SHA", "TLS_DH_RSA_WITH_SEED_CBC_SHA", "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "TLS_DH_anon_WITH_SEED_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_GCM_SHA256", "TLS_PSK_WITH_AES_256_GCM_SHA384", "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_CBC_SHA256", "TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS_PSK_WITH_NULL_SHA256", "TLS_PSK_WITH_NULL_SHA384", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_DHE_PSK_WITH_NULL_SHA256", "TLS_DHE_PSK_WITH_NULL_SHA384", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", "TLS_RSA_PSK_WITH_NULL_SHA256", "TLS_RSA_PSK_WITH_NULL_SHA384", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_ECDH_ECDSA_WITH_NULL_SHA", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_RSA_WITH_NULL_SHA", "TLS_ECDH_RSA_WITH_RC4_128_SHA", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_NULL_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_anon_WITH_NULL_SHA", "TLS_ECDH_anon_WITH_RC4_128_SHA", "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_RC4_128_SHA", "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_NULL_SHA", "TLS_ECDHE_PSK_WITH_NULL_SHA256", "TLS_ECDHE_PSK_WITH_NULL_SHA384", "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_WITH_AES_128_CCM", "TLS_RSA_WITH_AES_256_CCM", "TLS_RSA_WITH_AES_128_CCM_8", "TLS_RSA_WITH_AES_256_CCM_8", "TLS_PSK_WITH_AES_128_CCM", "TLS_PSK_WITH_AES_256_CCM", "TLS_PSK_WITH_AES_128_CCM_8", "TLS_PSK_WITH_AES_256_CCM_8"));

    /**
     * Weak protocol that must be excluded from the TLS configuration.
     */
    private static final List<String> WEAK_PROTOCOLS = Collections.unmodifiableList(Arrays.asList("SSL", "SSLv2", "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1"));


    private static final Logger LOGGER = LoggerFactory.getLogger(JettyServer.class);
    private final Server server;

    public JettyServer(int port, TlsSecurityConfiguration tlsSecurityConfiguration, Class<?>... serviceClasses) {
        this.server = new Server();
        ServerConnector http2Connector =
                new ServerConnector(server, getConnectionFactories(tlsSecurityConfiguration));
        http2Connector.setPort(port);
        server.addConnector(http2Connector);

        ServletContextHandler context = new ServletContextHandler(server, "/*", ServletContextHandler.GZIP);

        final ResourceConfig resourceConfig = new ResourceConfig();
        for (Class<?> serviceClass : serviceClasses) {
            resourceConfig.register(serviceClass);
        }
        ServletHolder servlet = new ServletHolder(new ServletContainer(resourceConfig));

        context.addServlet(servlet, "/*");

        try {
            server.start();
            LOGGER.info("Server {} has been started and listening on port {}", server, port);
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

    public static class TlsSecurityConfiguration {
        private final KeyStore keyStore;
        private final String certificateAlias;
        private final String certificatePassword;
        private final String protocol;

        public TlsSecurityConfiguration(KeyStore keyStore, String certificateAlias, String certificatePassword, String protocol) {
            this.keyStore = keyStore;
            this.certificateAlias = certificateAlias;
            this.certificatePassword = certificatePassword;
            this.protocol = protocol;
        }

        public static KeyStore getKeyStore(char[] password, String keystoreClasspathLocation) {
            final KeyStore keystore;
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
    }
}