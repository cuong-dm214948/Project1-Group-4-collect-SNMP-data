/*_############################################################################
  _## 
  _##  SNMP4J - DefaultSSLEngineConfiguration.java  
  _## 
  _##  Copyright (C) 2003-2022  Frank Fock (SNMP4J.org)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/

package org.snmp4j.transport.tls;

import org.snmp4j.TransportStateReference;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;

import javax.net.ssl.*;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The {@link DefaultSSLEngineConfiguration} implements the SSL engine configuration based on
 * {@link X509Certificate} trust management.
 *
 * @author Frank Fock
 * @since 3.6.0
 */
public class DefaultSSLEngineConfiguration implements SSLEngineConfigurator {

    private static final LogAdapter logger = LogFactory.getLogger(DefaultSSLEngineConfiguration.class);

    private final X509TlsTransportMappingConfig tlsTransportMappingConfig;
    private final TLSTMTrustManagerFactory trustManagerFactory;
    private final String defaultProtocolVersion;

    public DefaultSSLEngineConfiguration(X509TlsTransportMappingConfig tlsTransportMappingConfig,
                                         TLSTMTrustManagerFactory trustManagerFactory,
                                         String defaultProtocolVersion) {
        this.tlsTransportMappingConfig = tlsTransportMappingConfig;
        this.trustManagerFactory = trustManagerFactory;
        this.defaultProtocolVersion = defaultProtocolVersion;
    }

    public String getDefaultProtocolVersion() {
        return defaultProtocolVersion;
    }

    public TlsTransportMappingConfig<X509Certificate> getTlsTransportMappingConfig() {
        return tlsTransportMappingConfig;
    }

    public TLSTMTrustManagerFactory getTrustManagerFactory() {
        return trustManagerFactory;
    }

    @Override
    public void configure(SSLEngine sslEngine) {
        logger.debug("Configuring SSL engine, supported protocols are " +
                Arrays.asList(sslEngine.getSupportedProtocols()) + ", supported ciphers are " +
                Arrays.asList(sslEngine.getSupportedCipherSuites()) + ", https defaults are " +
                System.getProperty("https.cipherSuites"));
        String[] supportedCipherSuites = sslEngine.getEnabledCipherSuites();
        List<String> enabledCipherSuites = new ArrayList<String>(supportedCipherSuites.length);
        for (String cs : supportedCipherSuites) {
            if (!cs.contains("_anon_") && (!cs.contains("_NULL_"))) {
                enabledCipherSuites.add(cs);
            }
        }
        sslEngine.setEnabledCipherSuites(enabledCipherSuites.toArray(new String[0]));
        sslEngine.setEnabledProtocols(tlsTransportMappingConfig.getProtocolVersions());
        if (!sslEngine.getUseClientMode()) {
            sslEngine.setNeedClientAuth(true);
            sslEngine.setWantClientAuth(true);
            logger.info("Need client authentication set to true");
        }
        if (logger.isInfoEnabled()) {
            logger.info("Configured SSL engine, enabled protocols are " +
                    Arrays.asList(sslEngine.getEnabledProtocols()) + ", enabled ciphers are " +
                    Arrays.asList(sslEngine.getEnabledCipherSuites())+ ", supported ciphers are "+
                    Arrays.asList(sslEngine.getSupportedCipherSuites()));
        }
    }

    @Override
    public SSLContext getSSLContext(boolean useClientMode, TransportStateReference transportStateReference) throws GeneralSecurityException {
        try {
            String protocol = defaultProtocolVersion;
            if ((tlsTransportMappingConfig.getProtocolVersions() != null)
                    && (tlsTransportMappingConfig.getProtocolVersions().length > 0)) {
                protocol = tlsTransportMappingConfig.getProtocolVersions()[0];
            }
            return TLSTMUtil.createSSLContext(protocol,
                    tlsTransportMappingConfig.getKeyStore(), tlsTransportMappingConfig.getKeyStorePassword(),
                    tlsTransportMappingConfig.getTrustStore(), tlsTransportMappingConfig.getTrustStorePassword(),
                    transportStateReference, trustManagerFactory,
                    useClientMode, tlsTransportMappingConfig.getSecurityCallback(),
                    tlsTransportMappingConfig.getLocalCertificateAlias(),
                    tlsTransportMappingConfig.getPKIXRevocationChecker(),
                    tlsTransportMappingConfig.getX509CertificateRevocationListURI());
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to initialize SSLContext because of an NoSuchAlgorithmException: " +
                    e.getMessage(), e);
        }
        return null;
    }
}
