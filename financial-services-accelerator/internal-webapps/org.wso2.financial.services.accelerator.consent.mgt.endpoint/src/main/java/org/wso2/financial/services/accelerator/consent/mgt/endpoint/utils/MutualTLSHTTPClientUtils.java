package org.wso2.financial.services.accelerator.consent.mgt.endpoint.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.financial.services.accelerator.common.config.FinancialServicesConfigParser;
import org.wso2.financial.services.accelerator.common.exception.FinancialServicesException;
import org.wso2.financial.services.accelerator.common.util.HTTPClientUtils;

import java.security.KeyStore;

import javax.net.ssl.SSLContext;


/**
 * MutualTLSHTTPClientUtils extends the base HTTPClientUtils
 * by adding the ability to load a client certificate for mutual TLS.
 */
public class MutualTLSHTTPClientUtils extends HTTPClientUtils {

    // Supported TLS protocol version(s)
    private static final String[] SUPPORTED_TLS_PROTOCOLS = {"TLSv1.2"};
    // The alias of the client certificate to be attached.
    private static final String CLIENT_CERT_ALIAS = "wso2";
    private static final Log log = LogFactory.getLog(MutualTLSHTTPClientUtils.class);

    /**
     * Returns a CloseableHttpClient configured for mutual TLS.
     *
     * @return CloseableHttpClient with client certificate attached.
     * @throws FinancialServicesException if an error occurs during client creation.
     */
    public static CloseableHttpClient getMutualTLSHttpsClient() throws FinancialServicesException {

        // Create a socket factory that attaches the client certificate.
        SSLConnectionSocketFactory sslsf = createMutualTLSSocketFactory();

        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(HTTP_PROTOCOL, new PlainConnectionSocketFactory())
                .register(HTTPS_PROTOCOL, sslsf)
                .build();

        final PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager(socketFactoryRegistry);

        // Configure connection pooling using settings from the configuration parser.
        connectionManager.setMaxTotal(FinancialServicesConfigParser.getInstance().getConnectionPoolMaxConnections());
        connectionManager.setDefaultMaxPerRoute(FinancialServicesConfigParser.getInstance()
                .getConnectionPoolMaxConnectionsPerRoute());

        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    /**
     * Creates an SSLConnectionSocketFactory that loads both key material (for client authentication)
     * and trust material (for server certificate verification).
     *
     * @return SSLConnectionSocketFactory configured for mutual TLS.
     * @throws FinancialServicesException if the SSL context cannot be created.
     */
    private static SSLConnectionSocketFactory createMutualTLSSocketFactory() throws FinancialServicesException {

        // Retrieve the truststore location and password from the server configuration.
        String trustStoreLocation = ServerConfiguration.getInstance()
                .getFirstProperty("Security.TrustStore.Location");
        String trustStorePassword = ServerConfiguration.getInstance()
                .getFirstProperty("Security.TrustStore.Password");

        // Retrieve the keystore location and password from the server configuration.
        String keyStoreLocation = ServerConfiguration.getInstance()
                .getFirstProperty("Security.KeyStore.Location");
        String keyStorePassword = ServerConfiguration.getInstance()
                .getFirstProperty("Security.KeyStore.Password");

        // Load the keystore. In this case, we use the same keystore both as a trust store and as a client key store.
        KeyStore keyStore = loadKeyStore(keyStoreLocation, keyStorePassword);
        KeyStore trustStore = loadKeyStore(trustStoreLocation, trustStorePassword);

        SSLContext sslContext;
        try {
            sslContext = new SSLContextBuilder()
                    .loadKeyMaterial(keyStore, keyStorePassword.toCharArray(),
                            (map, socket) -> ServerConfiguration.getInstance()
                            .getFirstProperty("Security.KeyStore.KeyAlias"))
                    .loadTrustMaterial(trustStore, new TrustSelfSignedStrategy())
                    .build();
        } catch (Exception e) {
            throw new FinancialServicesException("Unable to create mutual TLS SSL context", e);
        }

        // Create and return the socket factory with the configured SSL context and hostname verifier.
        return new SSLConnectionSocketFactory(sslContext, SUPPORTED_TLS_PROTOCOLS, null, getX509HostnameVerifier());
    }
}
