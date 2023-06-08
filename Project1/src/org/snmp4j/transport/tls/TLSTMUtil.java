/*_############################################################################
  _## 
  _##  SNMP4J - TLSTMUtil.java  
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
import org.snmp4j.event.CounterEvent;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OctetString;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * The {@code TLSTMUtil} class implements common functions for {@link org.snmp4j.transport.TLSTM} and
 * {@link org.snmp4j.transport.DTLSTM}.
 *
 * @author Frank Fock
 * @since 3.0
 * @version 3.6.0
 */
public class TLSTMUtil {

    private static final LogAdapter logger = LogFactory.getLogger(TLSTMUtil.class);

    private static final int MD_SHA_PREFIX_LENGTH = "SHA".length();

    public static OctetString getFingerprint(X509Certificate cert) {
        OctetString certFingerprint = null;
        try {
            String algo = cert.getSigAlgName();
            if (algo.contains("with")) {
                algo = algo.substring(0, algo.indexOf("with"));
            }
            if (algo.length() > MD_SHA_PREFIX_LENGTH) {
                char c = algo.charAt(MD_SHA_PREFIX_LENGTH);
                switch (c) {
                    case '1':
                    case '2':
                    case '3':
                    case '5':
                        String algoPrefix = algo.substring(0, MD_SHA_PREFIX_LENGTH);
                        String algoSuffix = algo.substring(MD_SHA_PREFIX_LENGTH);
                        algo = algoPrefix + "-" +algoSuffix;
                        break;
                }
            }
            MessageDigest md = MessageDigest.getInstance(algo);
            md.update(cert.getEncoded());
            certFingerprint = new OctetString(md.digest());
        } catch (NoSuchAlgorithmException e) {
            logger.error("No such digest algorithm exception while getting fingerprint from " +
                    cert + ": " + e.getMessage(), e);
        } catch (CertificateEncodingException e) {
            logger.error("Certificate encoding exception while getting fingerprint from " +
                    cert + ": " + e.getMessage(), e);
        }
        return certFingerprint;
    }

    /**
     * Checks if any of the certificates in the provided array matches the given fingerprint. If the fingerprint to
     * match is {@code null} or zero length, {@code false} will be returned, because a matching cannot be performed.
     * @param x509Certificates
     *    the certificates to match.
     * @param fingerprint
     *    the searched fingerprint
     * @param useClientMode
     *    defines if server or client mode is active to emit the right counter events.
     * @param tlstmCounters
     *    the counters to increase on matching
     * @param logger
     *    where to log
     * @param eventSource
     *    the source object for events emitted by the matching.
     * @return
     *    {@code true} if there is a match, {@code false} if matching could not be performed due to {@code null} or
     *    zero length fingerprint
     * @throws CertificateException
     *    if there is no matching, but fingerprint is non-null and has a length greater than zero.
     */
    public static boolean isMatchingFingerprint(X509Certificate[] x509Certificates, OctetString fingerprint,
                                                boolean useClientMode, CounterSupport tlstmCounters, LogAdapter logger,
                                                Object eventSource)
            throws CertificateException
    {
        X509Certificate cert = x509Certificates[0];
        if ((fingerprint != null) && (fingerprint.length() > 0)) {
            OctetString certFingerprint = null;
            certFingerprint = TLSTMUtil.getFingerprint(cert);
            if (logger.isDebugEnabled()) {
                logger.debug("Comparing certificate fingerprint "+cert.getSubjectX500Principal()+
                        ": " + certFingerprint + " with " + fingerprint);
            }
            if (certFingerprint == null) {
                logger.error("Failed to determine fingerprint for certificate " + cert +
                        " and algorithm " + cert.getSigAlgName());
            } else if (certFingerprint.equals(fingerprint)) {
                if (logger.isInfoEnabled()) {
                    logger.info("Peer is trusted by fingerprint '" + fingerprint + "' of certificate: '" + cert + "'");
                }
                return true;
            }
            tlstmCounters.fireIncrementCounter(new CounterEvent(eventSource, (useClientMode) ?
                    SnmpConstants.snmpTlstmSessionInvalidServerCertificates :
                    SnmpConstants.snmpTlstmSessionInvalidClientCertificates));
            throw new CertificateException("Fingerprint of provided certificate "+cert.getSubjectX500Principal()+
                    "("+certFingerprint+")"+ " does not match "+fingerprint.toHexString());
        }
        return false;
    }

    public static Object getSubjAltName(Collection<List<?>> subjAltNames, int type) {
        if (subjAltNames != null) {
            for (List<?> entry : subjAltNames) {
                int t = (Integer) entry.get(0);
                if (t == type) {
                    return entry.get(1);
                }
            }
        }
        return null;
    }

    public static OctetString getIpAddressFromSubjAltName(Collection<List<?>> altNames) {
        Object entry = TLSTMUtil.getSubjAltName(altNames, 7);
        if (entry != null) {
            String ipAddress = ((String) entry).toLowerCase();
            if (ipAddress.indexOf(':') >= 0) {
                // IPv6 address
                StringBuilder buf = new StringBuilder(16);
                String[] bytes = ipAddress.split(":");
                for (String b : bytes) {
                    for (int diff = 2 - b.length(); diff > 0; diff--) {
                        buf.append('0');
                    }
                    buf.append(b);
                }
                return new OctetString(buf.toString());
            }
            return new OctetString(ipAddress);
        }
        return null;
    }

    public static SSLContext createSSLContext(String protocol, String keyStore, String keyStorePassword,
                                              String trustStore, String trustStorePassword,
                                              TransportStateReference transportStateReference,
                                              TLSTMTrustManagerFactory trustManagerFactory, boolean useClientMode,
                                              TlsTmSecurityCallback<X509Certificate> securityCallback,
                                              String localCertificateAlias,
                                              PKIXRevocationChecker pkixRevocationChecker, String crlURI)
            throws GeneralSecurityException
    {
        SSLContext sslContext = SSLContext.getInstance(protocol);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try (FileInputStream fisKeyStore = new FileInputStream(keyStore);
             FileInputStream fisTrustStore = new FileInputStream(trustStore)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fisKeyStore, (keyStorePassword != null) ? keyStorePassword.toCharArray() : null);
            if (logger.isInfoEnabled()) {
                logger.info("KeyStore '" + keyStore + "' contains: " + Collections.list(ks.aliases()));
            }
            filterCertificates(ks, transportStateReference, securityCallback, localCertificateAlias);
            KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(fisTrustStore, (trustStorePassword != null) ? trustStorePassword.toCharArray() : null);
            if (logger.isInfoEnabled()) {
                logger.info("TrustStore '" + trustStore + "' contains: " + Collections.list(ts.aliases()));
            }
            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, (keyStorePassword != null) ? keyStorePassword.toCharArray() : null);
            if (pkixRevocationChecker == null) {
                if (crlURI != null) {
                    PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(ts, new X509CertSelector());
                    addCRLCertStore(crlURI, pkixBuilderParameters);
                    tmf.init(new CertPathTrustManagerParameters(pkixBuilderParameters));
                }
                else {
                    tmf.init(ts);
                }
            }
            else {
                PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
                pkixParams.addCertPathChecker(pkixRevocationChecker);
                if (crlURI != null) {
                    addCRLCertStore(crlURI, pkixParams);
                }
                tmf.init(new CertPathTrustManagerParameters(pkixParams));
            }
            TrustManager[] trustManagers = tmf.getTrustManagers();
            if (logger.isDebugEnabled()) {
                logger.debug("SSL context initializing with TrustManagers: " + Arrays.asList(trustManagers) +
                        " and factory " + trustManagerFactory.getClass().getName());
            }
            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
            sslContext.init(kmf.getKeyManagers(),
                    new TrustManager[]{trustManagerFactory.create(trustManager, useClientMode, transportStateReference)},
                    null);
            return sslContext;
        } catch (NullPointerException npe) {
            String txt = "Failed to initialize SSLContext because of missing key store (javax.net.ssl.keyStore)";
            logger.error(txt);
            throw new KeyStoreException(txt, npe);
        } catch (KeyStoreException e) {
            logger.error("Failed to initialize SSLContext because of a KeyStoreException: " + e.getMessage(), e);
            throw e;
        } catch (KeyManagementException e) {
            logger.error("Failed to initialize SSLContext because of a KeyManagementException: " + e.getMessage(), e);
            throw e;
        } catch (UnrecoverableKeyException e) {
            logger.error("Failed to initialize SSLContext because of an UnrecoverableKeyException: " + e.getMessage(), e);
            throw e;
        } catch (CertificateException e) {
            logger.error("Failed to initialize SSLContext because of a CertificateException: " + e.getMessage(), e);
            throw e;
        } catch (FileNotFoundException e) {
            String txt = "Failed to initialize SSLContext because of a FileNotFoundException: " + e.getMessage();
            logger.error(txt, e);
            throw new KeyStoreException(txt, e);
        } catch (IOException e) {
            String txt = "Failed to initialize SSLContext because of an IOException: " + e.getMessage();
            logger.error(txt, e);
            throw new KeyStoreException(txt, e);
        }
    }

    /**
     * Creates a default revocation checker with CRL check only (no OCSP) and check is limited to end entity only.
     * @return
     *    a simple revocation checker to be used with
     *    {@link org.snmp4j.transport.TLSTM#setPKIXRevocationChecker(PKIXRevocationChecker)}.
     * @since 3.6.0
     */
    public static PKIXRevocationChecker createDefaultPKIXRevocationChecker() {
        CertPathBuilder cpb;
        try {
            cpb = CertPathBuilder.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker)cpb.getRevocationChecker();
        // Relaxed checking - avoid OCSP because of 33% overhead on TLS connection creation:
        revocationChecker.setOptions(EnumSet.of(
                PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
                PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                PKIXRevocationChecker.Option.NO_FALLBACK)); // do not fall back to OCSP
        return revocationChecker;
    }

    /**
     * Return the initialization parameters for a TrustManager for doing cert path validation with CRL revocation based
     * on a CRL file.
     * Currently, only the default {@code PKIX} is supported.
     *
     * @param crlFilePath
     *     the path to the CRL file that provides the CRL collection for checking revocation.
     * @param pkixBuilderParameters
     *     the {@link PKIXBuilderParameters} to modify.
     * @since 3.6.0
     */
    protected static void addCRLCertStore(String crlFilePath, PKIXBuilderParameters pkixBuilderParameters) {

        if (crlFilePath != null && crlFilePath.length() > 0) {
            Collection<? extends CRL> crls = getX509CRLs(crlFilePath);
            CertStoreParameters csp = new CollectionCertStoreParameters(crls);
            CertStore store = null;
            try {
                store = CertStore.getInstance("Collection", csp);
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            pkixBuilderParameters.addCertStore(store);
            pkixBuilderParameters.setRevocationEnabled(true);
        }
    }

    private static Collection<? extends CRL> getX509CRLs(String crlUrl)  {
        Collection<? extends CRL> crlList = Collections.emptyList();
        if (crlUrl != null) {
            URI uri;
            try {
                uri = new URI(crlUrl);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            try (InputStream is = uri.toURL().openStream()) {
                crlList = CertificateFactory.getInstance("X.509").generateCRLs(is);
            }
            catch (IOException | CRLException | CertificateException e) {
                throw new RuntimeException("Unable to load certificate revocation list '" + crlUrl + "' :" + e, e);
            }
        }
        return crlList;
    }


    private static void filterCertificates(KeyStore ks, TransportStateReference transportStateReference,
                                           TlsTmSecurityCallback<X509Certificate> securityCallback,
                                           String localCertificateAlias) {
        String localCertAlias = localCertificateAlias;
        if ((securityCallback != null) && (transportStateReference != null)) {
            localCertAlias = securityCallback.getLocalCertificateAlias(transportStateReference.getAddress());
            if (localCertAlias == null) {
                localCertAlias = localCertificateAlias;
            }
        }
        if (localCertAlias != null) {
            try {
                java.security.cert.Certificate[] chain = ks.getCertificateChain(localCertAlias);
                if (chain == null) {
                    logger.warn("Local certificate with alias '" + localCertAlias + "' not found. Known aliases are: " +
                            Collections.list(ks.aliases()));
                } else {
                    List<String> chainAliases = new ArrayList<String>(chain.length);
                    for (java.security.cert.Certificate certificate : chain) {
                        String alias = ks.getCertificateAlias(certificate);
                        if (alias != null) {
                            chainAliases.add(alias);
                        }
                    }
                    // now delete all others from key store
                    for (String alias : Collections.list(ks.aliases())) {
                        if (!chainAliases.contains(alias)) {
                            ks.deleteEntry(alias);
                        }
                    }
                }
            } catch (KeyStoreException e) {
                logger.error("Failed to get certificate chain for alias " +
                        localCertAlias + ": " + e.getMessage(), e);
            }
        }
    }

}

