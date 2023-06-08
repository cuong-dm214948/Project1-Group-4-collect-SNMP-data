/*_############################################################################
  _## 
  _##  SNMP4J - TLSTMExtendedTrustManager.java  
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

import org.snmp4j.CertifiedIdentity;
import org.snmp4j.TransportStateReference;
import org.snmp4j.event.CounterEvent;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.OctetString;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * TLSTM trust manager that implements the X509ExtendedTrustManager interface.
 *
 * @author Frank Fock
 * @since 2.5.7
 */
public class TLSTMExtendedTrustManager extends X509ExtendedTrustManager {

    private static final LogAdapter logger = LogFactory.getLogger(TLSTMExtendedTrustManager.class);

    X509TrustManager trustManager;
    private final boolean useClientMode;
    private final TransportStateReference tmStateReference;
    private final CounterSupport tlstmCounters;
    private final TlsTmSecurityCallback<X509Certificate> securityCallback;

    public TLSTMExtendedTrustManager(CounterSupport tlstmCounters,
                                     TlsTmSecurityCallback<X509Certificate> securityCallback,
                                     X509TrustManager trustManager,
                                     boolean useClientMode, TransportStateReference tmStateReference) {
        this.tlstmCounters = tlstmCounters;
        this.securityCallback = securityCallback;
        this.trustManager = trustManager;
        this.useClientMode = useClientMode;
        this.tmStateReference = tmStateReference;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        if (!checkClientTrustedIntern(x509Certificates)) {
            try {
                trustManager.checkClientTrusted(x509Certificates, s);
            } catch (CertificateException cex) {
                tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpenErrors));
                tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidClientCertificates));
                logger.warn("Client certificate validation failed for '" + x509Certificates[0] +
                        "': "+cex.getMessage());
                throw cex;
            }
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        if (checkServerTrustedByFingerprint(x509Certificates)) return;
        try {
            trustManager.checkServerTrusted(x509Certificates, s);
        } catch (CertificateException cex) {
            tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpenErrors));
            tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidServerCertificates));
            logger.warn("Server certificate validation failed for '" + x509Certificates[0] + "'");
            throw cex;
        }
        postCheckServerTrusted(x509Certificates);
    }

    private boolean isMatchingFingerprint(X509Certificate[] x509Certificates, OctetString fingerprint,
                                          boolean useClientMode) throws CertificateException
    {
        return TLSTMUtil.isMatchingFingerprint(x509Certificates, fingerprint, useClientMode, tlstmCounters, logger, this);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return getAcceptedIssuers(trustManager, securityCallback);
    }

    /**
     * Gets the accepted {@link X509Certificate}s from the given {@link X509TrustManager} and security callback.
     *
     * @param trustManager
     *         a X509TrustManager providing the accepted issuers.
     * @param securityCallback
     *         a security callback that is ask to accept any returned issuer.
     *
     * @return a probably empty or {@code null} array of accepted issuers.
     * @since 3.6.0
     */
    public static X509Certificate[] getAcceptedIssuers(X509TrustManager trustManager,
                                                       TlsTmSecurityCallback<X509Certificate> securityCallback) {
        X509Certificate[] accepted = trustManager.getAcceptedIssuers();
        if ((accepted != null) && (securityCallback != null)) {
            ArrayList<X509Certificate> acceptedIssuers = new ArrayList<>(accepted.length);
            for (X509Certificate cert : accepted) {
                try {
                    if (securityCallback.isAcceptedIssuer(cert)) {
                        acceptedIssuers.add(cert);
                    }
                }
                catch (CertificateException certex) {
                    // ignore
                    if (logger.isDebugEnabled()) {
                        logger.debug("Security callback " + securityCallback + " rejected " + cert.getSubjectX500Principal() +
                                ": " + certex.getMessage());
                    }
                }
            }
            return acceptedIssuers.toArray(new X509Certificate[0]);
        }
        return accepted;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        logger.debug("checkClientTrusted with socket");
        if (!checkClientTrustedIntern(x509Certificates)) {
            try {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    logger.debug("Extended checkClientTrusted with socket");
                    ((X509ExtendedTrustManager) trustManager).checkClientTrusted(x509Certificates, s, socket);
                } else {
                    trustManager.checkClientTrusted(x509Certificates, s);
                }
            } catch (CertificateException cex) {
                tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpenErrors));
                tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidClientCertificates));
                logger.warn("Client certificate validation failed for '" + x509Certificates[0] + "'");
                throw cex;
            }
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        logger.debug("checkClientTrusted with socket");
        if (checkServerTrustedByFingerprint(x509Certificates)) return;
        try {
            if (trustManager instanceof X509ExtendedTrustManager) {
                logger.debug("extended checkClientTrusted with socket");
                ((X509ExtendedTrustManager) trustManager).checkServerTrusted(x509Certificates, s, socket);
            } else {
                trustManager.checkServerTrusted(x509Certificates, s);
                postCheckServerTrusted(x509Certificates);
            }
            // RFC 6353 page 47 - snmpTlstmAddrTable, snmpTlstmAddrServerIdentity
            if (!checkServerTrustedBySubjectDN(x509Certificates)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Server certificate accepted by cert path validation only: "+
                            x509Certificates[0].getSubjectX500Principal());
                }
            }
        } catch (CertificateException cex) {
            tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpenErrors));
            tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidServerCertificates));
            if (logger.isWarnEnabled()) {
                logger.warn("Server certificate validation failed for '" + x509Certificates[0] + "'");
            }
            throw cex;
        }
    }

    /**
     * RFC 6353 page 47, snmpTlstmAddrServerIdentity
     */
    private boolean checkServerTrustedBySubjectDN(X509Certificate[] x509Certificates) throws CertificateException {
        Object entry = null;
        try {
            entry = TLSTMUtil.getSubjAltName(x509Certificates[0].getSubjectAlternativeNames(), 2);
        } catch (CertificateParsingException e) {
            logger.error("CertificateParsingException while verifying server certificate " +
                    Arrays.asList(x509Certificates));
            throw new CertificateException(e);
        }
        if (entry == null) {
            X500Principal x500Principal = x509Certificates[0].getSubjectX500Principal();
            if (x500Principal != null) {
                entry = x500Principal.getName();
            }
        }
        if (entry != null) {
            String dNSName = ((String) entry).toLowerCase();
            String hostName = ((IpAddress) tmStateReference.getAddress()).getInetAddress().getCanonicalHostName();
            if (dNSName.length() > 0) {
                if (dNSName.charAt(0) == '*') {
                    int pos = hostName.indexOf('.');
                    hostName = hostName.substring(pos);
                    dNSName = dNSName.substring(1);
                }
                if (hostName.equalsIgnoreCase(dNSName)) {
                    if (logger.isInfoEnabled()) {
                        logger.info("Peer hostname " + hostName + " matches dNSName " + dNSName);
                    }
                    return true;
                }
            }
            String msg = "Peer hostname " + hostName + " did not match dNSName " + dNSName;
            if (logger.isDebugEnabled()) {
                logger.debug(msg);
            }
            throw new CertificateException(msg);
        }
        return false;
    }

    private void postCheckServerTrusted(X509Certificate[] x509Certificates) throws CertificateException {
        if (useClientMode && (securityCallback != null)) {
            securityCallback.isServerCertificateAccepted(x509Certificates);
        }
    }

    private boolean checkServerTrustedByFingerprint(X509Certificate[] x509Certificates) throws CertificateException {
        if (TransportStateReference.hasCertifiedIdentity(tmStateReference)) {
            OctetString fingerprint = ((CertifiedIdentity)tmStateReference.getTarget()).getServerFingerprint();
            return TLSTMUtil.isMatchingFingerprint(x509Certificates, fingerprint, true, tlstmCounters, logger, this);
        }
        return false;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        logger.debug("checkClientTrusted with sslEngine");
        boolean clientTrustedByEndCertificateFingerprint = checkClientTrustedIntern(x509Certificates);
        if (!clientTrustedByEndCertificateFingerprint) {
            try {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    logger.debug("Extended checkClientTrusted with sslEngine");
                    ((X509ExtendedTrustManager) trustManager).checkClientTrusted(x509Certificates, s, sslEngine);
                } else {
                    trustManager.checkClientTrusted(x509Certificates, s);
                }
            } catch (CertificateException cex) {
                tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpenErrors));
                tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidClientCertificates));
                logger.warn("Client certificate validation failed for '" + x509Certificates[0] +
                        "': "+cex.getMessage());
                throw cex;
            }
        }
    }

    private boolean checkClientTrustedIntern(X509Certificate[] x509Certificates) throws CertificateException {
        if (TransportStateReference.hasCertifiedIdentity(tmStateReference)) {
            OctetString fingerprint = ((CertifiedIdentity)tmStateReference.getTarget()).getClientFingerprint();
            if (isMatchingFingerprint(x509Certificates, fingerprint, true)) {
                return true;
            }
        }
        if (!useClientMode && (securityCallback != null)) {
            if (securityCallback.isClientCertificateAccepted(x509Certificates[0])) {
                if (logger.isInfoEnabled()) {
                    logger.info("Client is trusted with certificate '" + x509Certificates[0] + "'");
                }
                return true;
            }
        }
        return false;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        logger.debug("checkServerTrusted with sslEngine");
        if (checkServerTrustedByFingerprint(x509Certificates)) return;
        try {
            if (trustManager instanceof X509ExtendedTrustManager) {
                logger.debug("Extended checkServerTrusted with sslEngine");
                ((X509ExtendedTrustManager) trustManager).checkServerTrusted(x509Certificates, s, sslEngine);
            } else {
                trustManager.checkServerTrusted(x509Certificates, s);
            }
        } catch (CertificateException cex) {
            tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpenErrors));
            tlstmCounters.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidServerCertificates));
            logger.warn("Server certificate validation failed for '" + x509Certificates[0] + "': "+ cex.getMessage());
            throw cex;
        }
        postCheckServerTrusted(x509Certificates);
    }

}
