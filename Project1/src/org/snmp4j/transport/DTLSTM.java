/*_############################################################################
  _## 
  _##  SNMP4J - DTLSTM.java  
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

package org.snmp4j.transport;

import org.snmp4j.SNMP4JSettings;
import org.snmp4j.TransportStateReference;
import org.snmp4j.event.CounterEvent;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.*;
import org.snmp4j.transport.tls.*;
import org.snmp4j.util.CommonTimer;
import org.snmp4j.util.SnmpConfigurator;
import org.snmp4j.util.ThreadPool;
import org.snmp4j.util.WorkerTask;

import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;
import static javax.net.ssl.SSLEngineResult.Status;

/**
 * The {@code DTLSTM} implements the Datagram Transport Layer Security Transport Mapping (TLS-TM) as defined by RFC
 * 5953 with the new IO API and {@link SSLEngine}.
 * <p>
 * It uses a single thread for processing incoming and outgoing messages. The thread is started when the
 * {@code listen} method is called, or when an outgoing request is sent using the {@code sendMessage} method.
 * </p>
 *
 * @author Frank Fock
 * @version 3.6.0
 * @since 3.0
 */
public class DTLSTM extends DefaultUdpTransportMapping implements X509TlsTransportMappingConfig,
        ConnectionOrientedTransportMapping<UdpAddress> {

    private static final LogAdapter logger =
            LogFactory.getLogger(DTLSTM.class);

    public static final int MAX_HANDSHAKE_LOOPS = 100;
    public static final int DEFAULT_SOCKET_TIMEOUT = 5000;
    public static final int DEFAULT_HANDSHAKE_TIMEOUT = 5000;
    public static final int DEFAULT_CONNECTION_TIMEOUT = 300000;
    private static final int DEFAULT_DTLS_HANDSHAKE_THREADPOOL_SIZE = 2;

    private long nextSessionID = 1;

    private final Map<InetSocketAddress, SocketEntry> sockets = new ConcurrentHashMap<>();
    private CommonTimer socketCleaner;
    private SSLEngineConfigurator sslEngineConfigurator;

    private TlsTmSecurityCallback<X509Certificate> securityCallback;
    private CounterSupport counterSupport;
    // 1 minute default timeout
    private long connectionTimeout = DEFAULT_CONNECTION_TIMEOUT;
    private int handshakeTimeout = DEFAULT_HANDSHAKE_TIMEOUT;

    public static final String DEFAULT_DTLSTM_PROTOCOLS = "DTLSv1.2";
    public static final int MAX_TLS_PAYLOAD_SIZE = 64 * 1024;

    private String localCertificateAlias;
    private String keyStore;
    private String keyStorePassword;
    private String trustStore;
    private String trustStorePassword;
    private String[] dtlsProtocols;
    private TLSTMTrustManagerFactory trustManagerFactory = new DefaultDTLSTMTrustManagerFactory();
    private PKIXRevocationChecker pkixRevocationChecker;
    private String x509CertificateRevocationListURI;

    private ThreadPool dtlsHandshakeThreadPool;
    private int dtlsHandshakeThreadPoolSize = DEFAULT_DTLS_HANDSHAKE_THREADPOOL_SIZE;

    private boolean serverEnabled = false;

    /**
     * Creates a default UDP transport mapping with the server for incoming messages disabled.
     *
     * @throws UnknownHostException
     *         if the local host cannot be determined.
     */
    public DTLSTM() throws IOException {
        super(new DtlsAddress(InetAddress.getLocalHost(), 0));
        this.counterSupport = CounterSupport.getInstance();
        super.maxInboundMessageSize = MAX_TLS_PAYLOAD_SIZE;
        setSocketTimeout(DEFAULT_SOCKET_TIMEOUT);
    }

    /**
     * Creates a TLS transport mapping with the server for incoming messages bind to the given DTLS address. The
     * {@code securityCallback} needs to be specified before {@link #listen()} is called.
     *
     * @param address
     *         server address to bind.
     *
     * @throws IOException
     *         on failure of binding a local port.
     * @since 3.3.2
     */
    public DTLSTM(DtlsAddress address) throws IOException {
        this(address, true);
    }

    /**
     * Creates a TLS transport mapping with the server for incoming messages bind to the given address. The
     * {@code securityCallback} needs to be specified before {@link #listen()} is called.
     *
     * @param address
     *         server address to bind.
     * @param serverEnabled
     *         defines the role of the underlying {@link SSLEngine}. Setting this to {@code false} enables the {@link
     *         SSLEngine#setUseClientMode(boolean)}.
     *
     * @throws IOException
     *         on failure of binding a local port.
     * @since 3.2.0
     */
    public DTLSTM(DtlsAddress address, boolean serverEnabled) throws IOException {
        super(address);
        this.serverEnabled = serverEnabled;
        super.maxInboundMessageSize = MAX_TLS_PAYLOAD_SIZE;
        this.counterSupport = CounterSupport.getInstance();
        setSocketTimeout(DEFAULT_SOCKET_TIMEOUT);
        try {
            if (Class.forName("javax.net.ssl.X509ExtendedTrustManager") != null) {
                Class<?> trustManagerFactoryClass =
                        Class.forName("org.snmp4j.transport.tls.DTLSTMExtendedTrustManagerFactory");
                Constructor<?> c = trustManagerFactoryClass.getConstructors()[0];
                TLSTMTrustManagerFactory trustManagerFactory = (TLSTMTrustManagerFactory) c.newInstance(this);
                setTrustManagerFactory(trustManagerFactory);
            }
        } catch (ClassNotFoundException ex) {
            //throw new IOException("Failed to load TLSTMTrustManagerFactory: "+ex.getMessage(), ex);
        } catch (InvocationTargetException | IllegalAccessException ex) {
            throw new IOException("Failed to init DTLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            throw new IOException("Failed to setup DTLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        } catch (InstantiationException ex) {
            throw new IOException("Failed to instantiate DTLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        }
    }

    /**
     * Creates a DTLS transport mapping that binds to the given address (interface) on the local host.
     *
     * @param securityCallback
     *         a security name callback to resolve X509 certificates to tmSecurityNames.
     * @param serverAddress
     *         the UdpAddress instance that describes the server address to listen on incoming connection requests.
     *
     * @throws IOException
     *         if the given address cannot be bound.
     */
    public DTLSTM(TlsTmSecurityCallback<X509Certificate> securityCallback, DtlsAddress serverAddress) throws IOException {
        this(securityCallback, serverAddress, CounterSupport.getInstance());
    }

    /**
     * Creates a TLS transport mapping that binds to the given address (interface) on the local host and runs as
     * a server.
     *
     * @param securityCallback
     *         a security name callback to resolve X509 certificates to tmSecurityNames.
     * @param serverAddress
     *         the UdpAddress instance that describes the server address to listen on incoming connection requests.
     * @param counterSupport
     *         The CounterSupport instance to be used to count events created by this TLSTM instance. To get a default
     *         instance, use {@link CounterSupport#getInstance()}.
     *
     * @throws IOException
     *         if the given address cannot be bound.
     */
    public DTLSTM(TlsTmSecurityCallback<X509Certificate> securityCallback,
                  DtlsAddress serverAddress, CounterSupport counterSupport) throws IOException {
        this(securityCallback, serverAddress, counterSupport, true);
    }

    /**
     * Creates a TLS transport mapping that binds to the given address (interface) on the local host.
     *
     * @param securityCallback
     *         a security name callback to resolve X509 certificates to tmSecurityNames.
     * @param serverAddress
     *         the UdpAddress instance that describes the server address to listen on incoming connection requests.
     * @param counterSupport
     *         The CounterSupport instance to be used to count events created by this TLSTM instance. To get a default
     *         instance, use {@link CounterSupport#getInstance()}.
     * @param serverEnabled
     *         defines the role of the underlying {@link SSLEngine}. Setting this to {@code false} enables the {@link
     *         SSLEngine#setUseClientMode(boolean)}.
     *
     * @throws IOException
     *         if the given address cannot be bound.
     * @since 3.2.0
     */
    public DTLSTM(TlsTmSecurityCallback<X509Certificate> securityCallback,
                  DtlsAddress serverAddress, CounterSupport counterSupport, boolean serverEnabled) throws IOException {
        this(serverAddress, serverEnabled);
        super.maxInboundMessageSize = MAX_TLS_PAYLOAD_SIZE;
        setSocketTimeout(DEFAULT_SOCKET_TIMEOUT);
        this.securityCallback = securityCallback;
        this.counterSupport = counterSupport;
    }

    /**
     * Starts the listener thread that accepts incoming messages. The thread is started in daemon mode and thus it will
     * not block application terminated. Nevertheless, the {@link #close()} method should be called to stop the listen
     * thread gracefully and free associated ressources.
     *
     * @throws IOException
     *         if the listen port could not be bound to the server thread.
     */
    @Override
    public synchronized void listen() throws IOException {
        dtlsHandshakeThreadPool =
                ThreadPool.create("DTLSTM_" + getListenAddress(), getDtlsHandshakeThreadPoolSize());
        if (connectionTimeout > 0) {
            // run as daemon
            socketCleaner = SNMP4JSettings.getTimerFactory().createTimer();
        }
        super.listen();
    }

    /**
     * Closes the socket and stops the listener thread and socket cleaner timer (if {@link #getSocketTimeout()} is
     * greater than zero).
     *
     * @throws IOException
     *         if the socket cannot be closed.
     */
    @Override
    public void close() throws IOException {
        for (SocketEntry socketEntry : sockets.values()) {
            socketEntry.closeSession();
        }
        super.close();
        if (dtlsHandshakeThreadPool != null) {
            dtlsHandshakeThreadPool.stop();
        }
        sockets.clear();
        if (socketCleaner != null) {
            socketCleaner.cancel();
        }
        socketCleaner = null;
        dtlsHandshakeThreadPool = null;
    }

    /**
     * Gets the {@link TransportType} this {@code TransportMapping} supports depending on {@link #isServerEnabled()}.
     *
     * @return {@link TransportType#receiver} if {@link #isServerEnabled()} is {@code true} and
     * {@link TransportType#sender} otherwise.
     * @since 3.2.0
     */
    @Override
    public TransportType getSupportedTransportType() {
        return (serverEnabled ? TransportType.any : TransportType.sender);
    }

    public int getDtlsHandshakeThreadPoolSize() {
        return dtlsHandshakeThreadPoolSize;
    }

    /**
     * Sets the maximum number of threads reserved for DTLS inbound connection handshake processing.
     *
     * @param dtlsHandshakeThreadPoolSize
     *         the thread pool size that gets effective when {@link #listen()} is called. Default is {@link
     *         #DEFAULT_DTLS_HANDSHAKE_THREADPOOL_SIZE}.
     */
    public void setDtlsHandshakeThreadPoolSize(int dtlsHandshakeThreadPoolSize) {
        this.dtlsHandshakeThreadPoolSize = dtlsHandshakeThreadPoolSize;
    }

    public String getLocalCertificateAlias() {
        if (localCertificateAlias == null) {
            return System.getProperty(SnmpConfigurator.P_TLS_LOCAL_ID, null);
        }
        return localCertificateAlias;
    }

    public String[] getProtocolVersions() {
        if (dtlsProtocols == null) {
            String s = System.getProperty(getProtocolVersionPropertyName(), DEFAULT_DTLSTM_PROTOCOLS);
            return s.split(",");
        }
        return dtlsProtocols;
    }

    /**
     * Returns the property name that is used by this transport mapping to determine the protocol versions from system
     * properties.
     *
     * @return a property name like {@link SnmpConfigurator#P_TLS_VERSION} or {@link SnmpConfigurator#P_DTLS_VERSION}.
     */
    @Override
    public String getProtocolVersionPropertyName() {
        return SnmpConfigurator.P_DTLS_VERSION;
    }

    /**
     * Sets the DTLS protocols/versions that DTLSTM should use during handshake. The default is defined by {@link
     * #DEFAULT_DTLSTM_PROTOCOLS}.
     *
     * @param dtlsProtocols
     *         an array of TLS protocol (version) names supported by the SunJSSE provider. The order in the array
     *         defines which protocol is tried during handshake first.
     *
     * @since 3.0
     */
    public void setProtocolVersions(String[] dtlsProtocols) {
        this.dtlsProtocols = dtlsProtocols;
    }

    public String getKeyStore() {
        if (keyStore == null) {
            return System.getProperty("javax.net.ssl.keyStore");
        }
        return keyStore;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public String getKeyStorePassword() {
        if (keyStorePassword == null) {
            return System.getProperty("javax.net.ssl.keyStorePassword");
        }
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getTrustStore() {
        if (trustStore == null) {
            return System.getProperty("javax.net.ssl.trustStore");
        }
        return trustStore;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
    }

    public String getTrustStorePassword() {
        if (trustStorePassword == null) {
            return System.getProperty("javax.net.ssl.trustStorePassword");
        }
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    /**
     * Sets the certificate alias used for client and server authentication by this TLSTM. Setting this property to a
     * value other than {@code null} filters out any certificates which are not in the chain of the given alias.
     *
     * @param localCertificateAlias
     *         a certificate alias which filters a single certification chain from the {@code javax.net.ssl.keyStore}
     *         key store to be used to authenticate this TLS transport mapping. If {@code null} no filtering appears,
     *         which could lead to more than a single chain available for authentication by the peer, which would
     *         violate the TLSTM standard requirements.
     */
    public void setLocalCertificateAlias(String localCertificateAlias) {
        this.localCertificateAlias = localCertificateAlias;
    }

    public CounterSupport getCounterSupport() {
        return counterSupport;
    }

    @Override
    public Class<? extends Address> getSupportedAddressClass() {
        return DtlsAddress.class;
    }

    /**
     * Returns a set of {@link DtlsAddress} and {@link UdpAddress}.
     *
     * @return a set of address classes with at least one element (see {@link #getSupportedAddressClass()}.
     */
    @Override
    public Set<Class<? extends Address>> getSupportedAddressClasses() {
        return new HashSet<>(Arrays.asList(DtlsAddress.class, UdpAddress.class));
    }

    public TlsTmSecurityCallback<X509Certificate> getSecurityCallback() {
        return securityCallback;
    }

    public void setSecurityCallback(TlsTmSecurityCallback<X509Certificate> securityCallback) {
        this.securityCallback = securityCallback;
    }

    public TLSTMTrustManagerFactory getTrustManagerFactory() {
        return trustManagerFactory;
    }

    /**
     * Set the TLSTM trust manager factory. Using a trust manager factory other than the default allows to add support
     * for Java 1.7 X509ExtendedTrustManager.
     *
     * @param trustManagerFactory
     *         a X.509 trust manager factory implementing the interface {@link TLSTMTrustManagerFactory}.
     *
     * @since 3.0.0
     */
    public void setTrustManagerFactory(TLSTMTrustManagerFactory trustManagerFactory) {
        if (trustManagerFactory == null) {
            throw new NullPointerException();
        }
        this.trustManagerFactory = trustManagerFactory;
    }

    @Override
    public UdpAddress getListenAddress() {
        UdpAddress actualListenAddress = null;
        DatagramSocket socketCopy = socket;
        if (socketCopy != null) {
            actualListenAddress = new DtlsAddress(socketCopy.getLocalAddress(), socketCopy.getLocalPort());
        }
        return actualListenAddress;
    }

    /**
     * Closes a connection to the supplied remote address, if it is open. This method is particularly useful when not
     * using a timeout for remote connections.
     *
     * @param remoteAddress
     *         the address of the peer socket.
     *
     * @return {@code true} if the connection has been closed and {@code false} if there was nothing to close.
     * @throws java.io.IOException
     *         if the remote address cannot be closed due to an IO exception.
     */
    public synchronized boolean close(UdpAddress remoteAddress) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Closing socket for peer address " + remoteAddress);
        }
        SocketEntry socketEntry =
                sockets.remove(new InetSocketAddress(remoteAddress.getInetAddress(), remoteAddress.getPort()));
        if (socketEntry != null) {
            socketEntry.closeSession();
            return true;
        }
        return false;
    }

    /**
     * Gets the connection timeout. This timeout specifies the time a connection may be idle before it is closed.
     *
     * @return long the idle timeout in milliseconds.
     */
    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Returns the {@code MessageLengthDecoder} used by this transport mapping.
     *
     * @return a MessageLengthDecoder instance.
     */
//    @Override
    public MessageLengthDecoder getMessageLengthDecoder() {
        throw new UnsupportedOperationException();
    }

    /**
     * Sets the {@code MessageLengthDecoder} that decodes the total message length from the header of a message.
     *
     * @param messageLengthDecoder
     *         a MessageLengthDecoder instance.
     */
//    @Override
    public void setMessageLengthDecoder(MessageLengthDecoder messageLengthDecoder) {
        throw new UnsupportedOperationException();
    }

    /**
     * Sets the connection timeout. This timeout specifies the time a connection may be idle before it is closed.
     *
     * @param connectionTimeout
     *         the idle timeout in milliseconds. A zero or negative value will disable any timeout and connections
     *         opened by this transport mapping will stay opened until they are explicitly closed.
     */
    public void setConnectionTimeout(long connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * Gets the {@link CommonTimer} that controls socket cleanup operations.
     *
     * @return a socket cleaner timer.
     * @since 3.0
     */
    @Override
    public CommonTimer getSocketCleaner() {
        return socketCleaner;
    }

    /**
     * Checks whether a server for incoming requests is enabled.
     *
     * @return boolean
     */
    public boolean isServerEnabled() {
        return serverEnabled;
    }

    /**
     * Sets whether a server for incoming requests should be created when the transport is set into listen state.
     * Setting this value has no effect until the {@link #listen()} method is called (if the transport is already
     * listening, {@link #close()} has to be called before).
     *
     * @param serverEnabled
     *         if {@code true} if the transport will listens for incoming requests after {@link #listen()} has been
     *         called.
     */
    public void setServerEnabled(boolean serverEnabled) {
        this.serverEnabled = serverEnabled;
    }

    /**
     * Sets the maximum buffer size for incoming requests. When SNMP packets are received that are longer than this
     * maximum size, the messages will be silently dropped and the connection will be closed.
     *
     * @param maxInboundMessageSize
     *         the length of the inbound buffer in bytes.
     */
    public void setMaxInboundMessageSize(int maxInboundMessageSize) {
        this.maxInboundMessageSize = maxInboundMessageSize;
    }

    /**
     * Gets the maximum number of milliseconds to wait for the DTLS handshake operation to succeed.
     *
     * @return the handshake timeout millis.
     */
    public int getHandshakeTimeout() {
        return handshakeTimeout;
    }

    /**
     * Sets the maximum number of milliseconds to wait for the DTLS handshake operation to succeed.
     *
     * @param handshakeTimeout
     *         the new handshake timeout millis.
     */
    public void setHandshakeTimeout(int handshakeTimeout) {
        this.handshakeTimeout = handshakeTimeout;
    }

    @Override
    public String getX509CertificateRevocationListURI() {
        return x509CertificateRevocationListURI;
    }

    @Override
    public void setX09CertificateRevocationListURI(String crlURI) {
        this.x509CertificateRevocationListURI = crlURI;
    }

    private synchronized void timeoutSocket(SocketEntry entry) {
        if ((connectionTimeout > 0) && (socketCleaner != null)) {
            socketCleaner.schedule(new SocketTimeout<>(this, entry), connectionTimeout);
        }
    }

    @Override
    protected List<DatagramPacket> prepareOutPackets(UdpAddress targetAddress, byte[] message,
                                                     TransportStateReference tmStateReference,
                                                     DatagramSocket socket, long timeoutMillis, int maxRetries)
            throws IOException {
        InetSocketAddress targetSocketAddress =
                new InetSocketAddress(targetAddress.getInetAddress(),
                        targetAddress.getPort());
        ByteBuffer outNet = ByteBuffer.allocate(MAX_TLS_PAYLOAD_SIZE);
        SocketEntry socketEntry = sockets.get(targetSocketAddress);
        List<DatagramPacket> packets = new ArrayList<>(1);
        if (socketEntry == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Did not find any existing DTLS session for " + targetAddress);
            }
            try {
                socketEntry = new SocketEntry(targetAddress, true, tmStateReference);
                sockets.put(targetSocketAddress, socketEntry);
                synchronized (socketEntry.outboundLock) {
                    HandshakeTask handshakeTask =
                            new HandshakeTask(socketEntry, socket, targetSocketAddress, null,
                                    timeoutMillis, maxRetries);
                    handshakeTask.run();
                }
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        } else if (logger.isDebugEnabled()) {
            logger.debug("Using existing DTLS session " + socketEntry.sessionID + " for sending packet to " + targetAddress);
        }
        ByteBuffer outApp = ByteBuffer.wrap(message);
        synchronized (socketEntry.outboundLock) {
            SSLEngineResult r = socketEntry.sslEngine.wrap(outApp, outNet);
            outNet.flip();
            Status rs = r.getStatus();
            if (rs == Status.BUFFER_OVERFLOW) {
                // the client maximum fragment size config does not work?
                throw new IOException("DTLSTM: Buffer overflow: incorrect server maximum fragment size");
            } else if (rs == Status.BUFFER_UNDERFLOW) {
                // unlikely
                throw new IOException("DTLSTM: Buffer underflow during wrapping");
            } else if (rs == Status.CLOSED) {
                throw new IOException("DTLSTM: SSLEngine has closed");
            }   // otherwise, SSLEngineResult.Status.OK
            // SSLEngineResult.Status.OK:
            if (outNet.hasRemaining()) {
                byte[] ba = new byte[outNet.remaining()];
                outNet.get(ba);
                DatagramPacket packet = new DatagramPacket(ba, ba.length, targetSocketAddress);
                packets.add(packet);
            }
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Prepared " + packets + " for " + targetAddress);
        }
        return packets;
    }

    protected List<DatagramPacket> onReceiveTimeout(SSLEngine engine, SocketAddress socketAddr) throws IOException {

        HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == NOT_HANDSHAKING) {
            return new ArrayList<DatagramPacket>();
        } else {
            // retransmission of handshake messages
            return produceHandshakePackets(engine, socketAddr);
        }
    }

    @Override
    public PKIXRevocationChecker getPKIXRevocationChecker() {
        return this.pkixRevocationChecker;
    }

    @Override
    public void setPKIXRevocationChecker(PKIXRevocationChecker pkixRevocationChecker) {
        this.pkixRevocationChecker = pkixRevocationChecker;
    }

    class HandshakeTask implements WorkerTask {
        private boolean endLoops = false;
        private final Object joinLock = new Object();

        private final SocketEntry socketEntry;
        private final DatagramSocket socket;
        private final SocketAddress peerAddr;
        private final DatagramPacket receivedPacket;
        private final long handshakeTimeout;
        private final int maxRetries;

        private int retries = 0;

        public HandshakeTask(SocketEntry socketEntry, DatagramSocket socket, SocketAddress peerAddr,
                             DatagramPacket receivedPacket, long handshakeTimeout, int maxRetries) {
            this.socketEntry = socketEntry;
            this.socket = socket;
            this.peerAddr = peerAddr;
            this.receivedPacket = receivedPacket;
            this.handshakeTimeout = handshakeTimeout;
            this.maxRetries = maxRetries;
        }

        public void run() {
            socketEntry.setHandshakeFinished(false);
            DatagramPacket received = receivedPacket;
            SSLEngine engine = socketEntry.sslEngine;
            engine.setEnableSessionCreation(true);
            int loops = MAX_HANDSHAKE_LOOPS;
            ByteBuffer iNet = null;
            ByteBuffer iApp = null;
            UdpAddress peerAddress = socketEntry.getPeerAddress();
            InetSocketAddress peerSocketAddress =
                    new InetSocketAddress(peerAddress.getInetAddress(), peerAddress.getPort());
            try {
                engine.beginHandshake();
                long startTime = System.nanoTime();
                long timeoutMillis = handshakeTimeout <= 0 ? getHandshakeTimeout() : handshakeTimeout;
                while (!endLoops && !engine.isInboundDone() && (sockets.containsKey(peerSocketAddress)) &&
                        (((System.nanoTime() - startTime) / SnmpConstants.MILLISECOND_TO_NANOSECOND) < timeoutMillis)) {
                    if (--loops < 0) {
                        stopLoops();
                        throw new IOException("DTLSTM: Too much loops to produce handshake packets");
                    }
                    HandshakeStatus hs = engine.getHandshakeStatus();
                    if (logger.isDebugEnabled()) {
                        logger.debug("Processing handshake status " + hs + " in loop #" + (MAX_HANDSHAKE_LOOPS - loops));
                    }
                    Status rs = null;
                    while (!endLoops && (hs == NEED_UNWRAP || hs == NEED_UNWRAP_AGAIN)) {
                        if (hs != NEED_UNWRAP_AGAIN) {
                            if (received == null && !((iNet != null) && (iNet.hasRemaining()))) {
                                if (isListening()) {
                                    long timeout = timeoutMillis - ((System.nanoTime() - startTime) /
                                            SnmpConstants.MILLISECOND_TO_NANOSECOND);
                                    if (timeout > 0) {
                                        synchronized (socketEntry) {
                                            try {
                                                if (socketEntry.inboundPacketQueue.isEmpty()) {
                                                    logger.debug("Waiting for next handshake packet timeout=" + timeout);
                                                    socketEntry.wait(timeoutMillis);
                                                }
                                            } catch (InterruptedException iex) {
                                                // ignore
                                            }
                                            if (engine.getHandshakeStatus() == NOT_HANDSHAKING) {
                                                if (logger.isDebugEnabled()) {
                                                    logger.debug("Handshake finished already by other thread");
                                                }
                                                return;
                                            }
                                            synchronized (socketEntry.inboundLock) {
                                                received = socketEntry.inboundPacketQueue.pollFirst();
                                                if (logger.isDebugEnabled() && (received != null)) {
                                                    logger.debug("Polled DTLS packet with length " + received.getLength());
                                                }
                                            }
                                        }
                                    } else {
                                        stopLoops();

                                    }
                                    if (received == null) {
                                        continue;
                                    }
                                } else {
                                    byte[] buf = new byte[getMaxInboundMessageSize()];
                                    // receive ClientHello request and other SSL/TLS records
                                    received = new DatagramPacket(buf, buf.length);
                                    try {
                                        socket.receive(received);
                                    } catch (SocketTimeoutException ste) {
                                        if (logger.isInfoEnabled()) {
                                            logger.info("Socket timeout while receiving DTLS handshake packet");
                                        }
                                        if (maxRetries > retries++) {
                                            synchronized (socketEntry.outboundLock) {
                                                // ignore and handle later below
                                                List<DatagramPacket> packets = onReceiveTimeout(engine, peerAddr);
                                                for (DatagramPacket p : packets) {
                                                    socket.send(p);
                                                    if (logger.isDebugEnabled()) {
                                                        logger.debug("Sent " + new OctetString(p.getData()).toHexString() +
                                                                " to " + p.getAddress() + ":" + p.getPort());
                                                    }
                                                }
                                            }
                                        } else {
                                            stopLoops();
                                        }
                                        break;
                                    }
                                }
                            }
                            if (received != null) {
                                if (((iNet == null) || (!iNet.hasRemaining()))) {
                                    iNet = ByteBuffer.wrap(received.getData(), 0, received.getLength());
                                } else {
                                    iNet.compact();
                                    iNet.put(received.getData(), 0, received.getLength());
                                    iNet.flip();
                                }
                            }
                        }
                        iApp = ByteBuffer.allocate(getMaxInboundMessageSize());
                        received = null;
                        synchronized (socketEntry.inboundLock) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("unrwap start: iNet=" + iNet + ",iApp=" + iApp);
                            }
                            SSLEngineResult r = engine.unwrap(iNet, iApp);
                            rs = r.getStatus();
                            hs = r.getHandshakeStatus();
                            if (logger.isDebugEnabled()) {
                                logger.debug("unrwap done: iNet=" + iNet + ",iApp=" + iApp + ",rs=" + rs + ",hs=" + hs);
                            }
                        }
                        if (rs == Status.BUFFER_OVERFLOW) {
                            // the client maximum fragment size config does not work?
                            throw new IOException("DTLSTM: Buffer overflow: incorrect client maximum fragment size");
                        } else if (rs == Status.BUFFER_UNDERFLOW) {
                            // bad packet, or the client maximum fragment size
                            logger.warn("DTLS buffer underflow iNet=" + iNet + ",iApp=" + iApp);
                            // config does not work?
                            if (hs == NOT_HANDSHAKING) {
                                stopLoops();
                                break;
                            } // otherwise, ignore this packet
                            continue;
                        } else if (rs == Status.CLOSED) {
                            stopLoops();
                        }   // otherwise, SSLEngineResult.Status.OK:
                        if (rs != Status.OK) {
                            break;
                        }
                    }
                    if (hs == NEED_WRAP) {
                        synchronized (socketEntry.outboundLock) {
                            List<DatagramPacket> packets = produceHandshakePackets(engine, peerAddr);
                            for (DatagramPacket p : packets) {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Sending handshake packet with length " + p.getLength() +
                                            " [" + new OctetString(p.getData()).toHexString() +
                                            "] to " + p.getAddress() + ":" + p.getPort());
                                }
                                socket.send(p);
                            }
                        }
                    } else if (hs == NEED_TASK) {
                        runDelegatedTasks(engine);
                    } else if (hs == NOT_HANDSHAKING) {
                        // OK, time to do application data exchange.
                        stopLoops();
                    } else if (hs == FINISHED) {
                        stopLoops();
                    }
                }
            } catch (IOException iox) {
                logger.error("DTLS handshake failed for " + peerAddr +
                        " failed with IO exception:" + iox.getMessage(), iox);
            }
            HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs != NOT_HANDSHAKING) {
                sockets.remove(peerSocketAddress);
                logger.error("DTLS handshake failed for " + peerAddr + ", status is "+hs+
                        ": Not ready for application data yet, giving up");
                socketEntry.closeSession();
            } else {
                socketEntry.setHandshakeFinished(true);
                if (logger.isInfoEnabled()) {
                    logger.info("SSL handshake completed for " + peerAddr);
                }
                timeoutSocket(socketEntry);
                TransportStateEvent e = new TransportStateEvent(DTLSTM.this, socketEntry.getPeerAddress(),
                        TransportStateEvent.STATE_CONNECTED, null);
                fireConnectionStateChanged(e);
            }
            stopLoops();
        }

        private void stopLoops() {
            this.endLoops = true;
            synchronized (joinLock) {
                joinLock.notifyAll();
            }
        }

        /**
         * The {@code WorkerPool} might call this method to hint the active {@code WorkTask} instance to complete
         * execution as soon as possible.
         */
        @Override
        public void terminate() {
            endLoops = true;
        }

        /**
         * Waits until this task has been finished.
         *
         * @throws InterruptedException
         *         if the join has been interrupted by another thread.
         */
        @Override
        public void join() throws InterruptedException {
            synchronized (joinLock) {
                while (!endLoops) {
                    joinLock.wait(10);
                }
            }
        }

        /**
         * Interrupts this task.
         *
         * @see Thread#interrupt()
         */
        @Override
        public void interrupt() {
            synchronized (socketEntry) {
                socketEntry.notify();
            }
        }
    }

    @Override
    public boolean isAsyncMsgProcessingSupported() {
        // Is needed to correctly run DTLS handshake and other inbound packets
        return true;
    }

    @Override
    public void setAsyncMsgProcessingSupported(boolean asyncMsgProcessingSupported) {
        if (!asyncMsgProcessingSupported) {
            throw new IllegalArgumentException("Async message processing cannot be disabled for DTLS");
        }
    }

    @Override
    protected void fireProcessMessage(DatagramPacket packet, ByteBuffer bis, TransportStateReference stateReference) {
        fireProcessMessage(new DtlsAddress(packet.getAddress(), packet.getPort()), bis, stateReference);
    }

    @Override
    protected ByteBuffer prepareInPacket(DatagramPacket packet, byte[] buf, TransportStateReference tmStateReference)
            throws IOException {
        InetAddress peerAddress = packet.getAddress();
        InetSocketAddress peerSocketAddress =
                new InetSocketAddress(peerAddress, packet.getPort());
        SocketEntry entry = sockets.get(peerSocketAddress);
        if (logger.isDebugEnabled()) {
            logger.debug("Preparing inbound DTLS packet from " + peerSocketAddress);
        }
        if (entry == null) {
            if (logger.isInfoEnabled()) {
                logger.info("New DTLS connection from " + peerSocketAddress + " using " +
                        (isServerEnabled() ? "server" : "client") + " role");
            }
            try {
                entry = new SocketEntry(new DtlsAddress(peerAddress, packet.getPort()),
                        !isServerEnabled(), tmStateReference);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to accept new DTLS connection from " + peerAddress + " due to: " +
                        e.getMessage(), e);
            }
            synchronized (entry.inboundLock) {
                SocketEntry otherEntry = sockets.get(peerSocketAddress);
                final SocketEntry handshakeEntry = entry;
                if (otherEntry == null) {
                    sockets.put(peerSocketAddress, entry);
                    HandshakeTask handshakeTask = new HandshakeTask(handshakeEntry, socket,
                            peerSocketAddress, packet, 0, 0);
                    dtlsHandshakeThreadPool.execute(handshakeTask);
                    return null;
                } else {
                    entry = otherEntry;
                }
            }
        }
        // note that socket has been used
        entry.used();
        if (!entry.isHandshakeFinished()) {
            logger.debug("Adding DTLS packet to handshake queue: " + packet);
            synchronized (entry) {
                entry.inboundPacketQueue.add(packet);
                entry.notify();
            }
        } else {
            ByteBuffer inAppBuffer = ByteBuffer.allocate(getMaxInboundMessageSize());
            ByteBuffer inNetBuffer;
            synchronized (entry.outboundLock) {
                inNetBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Read " + packet.getLength() + " bytes from " + peerSocketAddress);
                logger.debug("DTLS inNetBuffer: " + inNetBuffer);
            }
            if (inNetBuffer.hasRemaining()) {
                SSLEngineResult result;
                synchronized (entry.inboundLock) {
                    result = entry.sslEngine.unwrap(inNetBuffer, inAppBuffer);
                    switch (result.getStatus()) {
                        case BUFFER_OVERFLOW:
                            // TODO handle overflow
                            logger.error("DTLS BUFFER_OVERFLOW");
                            throw new RuntimeException("DTLS BUFFER_OVERFLOW");
                    }
                    if (runDelegatedTasks(entry.sslEngine)) {
                        if (logger.isInfoEnabled()) {
                            logger.info("SSL session established for peer " + peerSocketAddress);
                        }
                        if (result.bytesProduced() > 0) {
                            inAppBuffer.flip();
                            logger.debug("SSL established, dispatching inappBuffer=" + inAppBuffer);
                            // SSL session is established
                            entry.checkTransportStateReference(tmStateReference);
                            return inAppBuffer;
                        }
                    }
                }
            }
        }
        return null;
    }


    /**
     * If the result indicates that we have outstanding tasks to do, go ahead and run them in this thread.
     *
     * @param engine
     *         the SSLEngine wrap/unwrap result.
     *
     * @return {@code true} if processing of delegated tasks has been finished, {@code false} otherwise.
     */
    boolean runDelegatedTasks(SSLEngine engine) {
        Runnable runnable;
        while ((runnable = engine.getDelegatedTask()) != null) {
            runnable.run();
        }
        HandshakeStatus hs = engine.getHandshakeStatus();
        return hs != NEED_TASK;
    }


    protected List<DatagramPacket> produceHandshakePackets(SSLEngine sslEngine,
                                                           SocketAddress socketAddress) throws IOException {
        List<DatagramPacket> packets = new ArrayList<>();
        boolean endLoops = false;
        int loops = MAX_HANDSHAKE_LOOPS;
        while (!endLoops) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            ByteBuffer oNet = ByteBuffer.allocate(getMaxOutboundMessageSize());
            ByteBuffer oApp = ByteBuffer.allocate(0);
            SSLEngineResult r = sslEngine.wrap(oApp, oNet);
            oNet.flip();

            Status rs = r.getStatus();
            HandshakeStatus hs = r.getHandshakeStatus();
            if (rs == Status.BUFFER_OVERFLOW) {
                // the client maximum fragment size config does not work?
                throw new IOException("Buffer overflow: " +
                        "incorrect server maximum fragment size");
            } else if (rs == Status.BUFFER_UNDERFLOW) {
                // bad packet, or the client maximum fragment size
                // config does not work?
                if (hs != NOT_HANDSHAKING) {
                    throw new IOException("Buffer underflow: " +
                            "incorrect server maximum fragment size");
                } // otherwise, ignore this packet
            } else if (rs == Status.CLOSED) {
                throw new IOException("SSLEngine has closed");
            }   // otherwise, SSLEngineResult.Status.OK

            // SSLEngineResult.Status.OK:
            if (oNet.hasRemaining()) {
                byte[] ba = new byte[oNet.remaining()];
                oNet.get(ba);
                DatagramPacket packet = createHandshakePacket(ba, socketAddress);
                packets.add(packet);
            }
            boolean endInnerLoop = false;
            HandshakeStatus nhs = hs;
            while (!endInnerLoop) {
                if (nhs == NEED_TASK) {
                    runDelegatedTasks(sslEngine);
                    nhs = sslEngine.getHandshakeStatus();
                } else if ((nhs == FINISHED) ||
                        (nhs == NEED_UNWRAP) ||
                        (nhs == NEED_UNWRAP_AGAIN) ||
                        (nhs == NOT_HANDSHAKING)) {
                    endInnerLoop = true;
                    endLoops = true;
                } else if (nhs == NEED_WRAP) {
                    endInnerLoop = true;
                }
            }
        }
        return packets;
    }

    protected DatagramPacket createHandshakePacket(byte[] buf, SocketAddress socketAddr) {
        return new DatagramPacket(buf, buf.length, socketAddr);
    }


    class SocketEntry extends AbstractServerSocket<UdpAddress> {
        private final SSLEngine sslEngine;
        private final long sessionID;
        private final TransportStateReference tmStateReference;
        private boolean handshakeFinished;

        private final Object outboundLock = new Object();
        private final Object inboundLock = new Object();

        private final LinkedList<DatagramPacket> inboundPacketQueue = new LinkedList<>();

        public SocketEntry(UdpAddress address, boolean useClientMode,
                           TransportStateReference tmStateReference) throws GeneralSecurityException {
            super(address);
            this.tmStateReference = tmStateReference;
            if (tmStateReference == null) {
                counterSupport.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionAccepts));
            }
            SSLEngineConfigurator sslEngineConfigurator = ensureSslEngineConfigurator();
            SSLContext sslContext = sslEngineConfigurator.getSSLContext(useClientMode, tmStateReference);
            if (sslContext == null) {
                throw new RuntimeException("Failed to initialize SSLContext");
            }
            this.sslEngine = sslContext.createSSLEngine(address.getInetAddress().getHostName(), address.getPort());
            sslEngine.setUseClientMode(useClientMode);
            sslEngine.setNeedClientAuth(true);
            SSLParameters parameters = this.sslEngine.getSSLParameters();
            parameters.setMaximumPacketSize(getMaxInboundMessageSize());
            this.sslEngine.setSSLParameters(parameters);
            sslEngineConfigurator.configure(sslEngine);
            synchronized (DTLSTM.this) {
                sessionID = nextSessionID++;
            }
        }


        public String toString() {
            return "SocketEntry[peerAddress=" + getPeerAddress() + ",socket=" + socket + ",lastUse=" +
                    new Date(getLastUse() / SnmpConstants.MILLISECOND_TO_NANOSECOND) +
                    "]";
        }

        public void checkTransportStateReference(TransportStateReference tmStateReference) {
            tmStateReference.setTransport(DTLSTM.this);
            if (tmStateReference.getTransportSecurityLevel().equals(SecurityLevel.undefined)) {
                tmStateReference.setTransportSecurityLevel(SecurityLevel.authPriv);
            }
            OctetString securityName = tmStateReference.getSecurityName();
            if (securityCallback != null) {
                try {
                    securityName = securityCallback.getSecurityName(
                            (X509Certificate[]) sslEngine.getSession().getPeerCertificates());
                } catch (SSLPeerUnverifiedException e) {
                    logger.error("SSL peer '" + getPeerAddress() + "' is not verified by security callback " +
                            securityCallback + " : " + e.getMessage(), e);
                    sslEngine.setEnableSessionCreation(false);
                }
            } else if (securityName == null) {
                logger.warn("No security callback configured to match DTLS peer certificate to local security name");
            }
            tmStateReference.setSecurityName(securityName);
        }

        public boolean isHandshakeFinished() {
            return handshakeFinished;
        }

        public synchronized void setHandshakeFinished(boolean handshakeFinished) {
            this.handshakeFinished = handshakeFinished;
            notifyAll();
        }

        public long getSessionID() {
            return sessionID;
        }

        public void closeSession() {
            if (sslEngine.getSession().isValid()) {
                ByteBuffer outNetBuffer = ByteBuffer.allocate(getMaxOutboundMessageSize());
                try {
                    SSLEngineResult sslEngineResult;
                    do {
                        sslEngineResult = sslEngine.wrap(ByteBuffer.allocate(0), outNetBuffer);
                        outNetBuffer.flip();
                        socket.send(new DatagramPacket(outNetBuffer.array(), outNetBuffer.limit(),
                                getPeerAddress().getInetAddress(), getPeerAddress().getPort()));
                    }
                    while ((sslEngineResult.getStatus() != Status.CLOSED) &&
                            (sslEngineResult.getHandshakeStatus() == NEED_WRAP));
                } catch (Exception e) {
                    logger.error("DTLSM: Exception while closing TLS session " + this + ": " + e.getMessage(), e);
                }
            }
            sslEngine.closeOutbound();
            counterSupport.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionServerCloses));
            TransportStateEvent e =
                    new TransportStateEvent(DTLSTM.this, getPeerAddress(), TransportStateEvent.STATE_CLOSED,
                            null);
            fireConnectionStateChanged(e);
        }
    }

    public SSLEngineConfigurator getSslEngineConfigurator() {
        return sslEngineConfigurator;
    }

    public void setSslEngineConfigurator(SSLEngineConfigurator sslEngineConfigurator) {
        this.sslEngineConfigurator = sslEngineConfigurator;
    }

    /**
     * Returns the configured {@link #setSslEngineConfigurator(SSLEngineConfigurator)} or the {@link
     * org.snmp4j.transport.tls.DefaultSSLEngineConfiguration} which will then become the configured SSL engine
     * configurator. This method is not synchronized against concurrent execution of {@link
     * #setSslEngineConfigurator(SSLEngineConfigurator)}.
     *
     * @return a non-null {@link SSLEngineConfigurator}.
     * @since 3.0.5
     */
    protected SSLEngineConfigurator ensureSslEngineConfigurator() {
        if (sslEngineConfigurator == null) {
            sslEngineConfigurator =
                    new org.snmp4j.transport.tls.DefaultSSLEngineConfiguration(this, trustManagerFactory,
                            DEFAULT_DTLSTM_PROTOCOLS);
        }
        return sslEngineConfigurator;
    }

    private class DefaultDTLSTMTrustManagerFactory implements TLSTMTrustManagerFactory {
        public X509TrustManager create(X509TrustManager trustManager, boolean useClientMode,
                                       TransportStateReference tmStateReference) {
            return new org.snmp4j.transport.tls.TLSTMExtendedTrustManager(counterSupport, securityCallback,
                    trustManager, useClientMode, tmStateReference);
        }
    }

}
