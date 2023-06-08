/*_############################################################################
  _## 
  _##  SNMP4J - SnmpBuilder.java  
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
package org.snmp4j.fluent;

import org.snmp4j.*;
import org.snmp4j.cfg.EngineBootsProvider;
import org.snmp4j.cfg.EngineIdProvider;
import org.snmp4j.cfg.SnmpEngineIdProvider;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.TSM;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.*;
import org.snmp4j.transport.tls.TlsTmSecurityCallback;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;

/**
 * Builds a {@link Snmp} instance through step-by-step configuration using a fluent interface design pattern.
 * This {@link SnmpBuilder} is the starting context. It creates the non-fluent {@link Snmp} instance that is
 * needed to as first parameter for {@link SnmpCompletableFuture#send(Snmp, Target, PDU, Object...)} which
 * actually sends the SNMP message to a {@link Target}.
 * Use {@link TargetBuilder} and {@link PduBuilder} to create the other two mandatory parameters. To get a
 * {@link TargetBuilder} call {@link #target(Address)}. The {@link PduBuilder} can be then retrieved from that
 * {@link TargetBuilder} by calling {@link TargetBuilder#pdu()}.
 * For a complete code sample see https://snmp4j.org.
 *
 * <pre>
 *  //Brief flow description of using the new SNMP4J fluent interface:
 *  SnmpBuilder.udp()...build() =&gt; Snmp
 *  SnmpBuilder.target(..) =&gt; TargetBuilder
 *      TargetBuilder.user(..)...done()...build() =&gt; Target
 *      TargetBuilder.pdu()...build() =&gt; PDUrequest
 *  SnmpCompletableFuture.send(Snmp, Target, PDUrequest) =&gt; SnmpCompletableFuture
 *  SnmpCompletableFuture.get() =&gt; PDUresponse
 * </pre>
 *
 * @author Frank Fock
 * @since 3.5.0
 */
public class SnmpBuilder {

    protected final Snmp snmp;
    protected final SecurityProtocols securityProtocols;
    protected final SecurityModels securityModels;
    protected CounterSupport counterSupport;
    protected ThreadPool multiThreadedDispatcherPool;
    protected String responderPoolName = "SnmpDispatcherPool";
    protected EngineIdProvider engineIdProvider;
    protected EngineBootsProvider engineBootsProvider;
    protected byte[] localEngineID;

    /**
     * Creates an {@link SnmpBuilder} with a default constructed {@link Snmp} instance.
     */
    public SnmpBuilder() {
        this(new Snmp());
    }

    /**
     * Creates an {@link SnmpBuilder} with an preconfigured {@link Snmp} instance, which must provide a non
     * {@code null} {@link Snmp#getMessageDispatcher()}. {@link CounterSupport} is set to
     * {@link CounterSupport#getInstance()}, {@link SecurityProtocols} are initialized with
     * {@link SecurityProtocols.SecurityProtocolSet#defaultSecurity}, and {@link SecurityModels} is initialized with
     * its default construct (i.e. no security models).
     * @param snmp
     *    a non-null {@link Snmp} instance.
     */
    protected SnmpBuilder(Snmp snmp) {
        this.snmp = snmp;
        this.snmp.getMessageDispatcher().addCommandResponder(snmp);
        counterSupport = CounterSupport.getInstance();
        securityProtocols = new SecurityProtocols(SecurityProtocols.SecurityProtocolSet.defaultSecurity);
        securityModels = new SecurityModels();
    }

    /**
     * Creates a {@link TargetBuilder} for the specified target {@link Address}.
     * @param address
     *    a {@link TransportIpAddress}.
     * @param <A>
     *    the transport address type.
     * @return
     *    a {@link TargetBuilder} instance.
     */
    public <A extends Address> TargetBuilder<A> target(A address) {
        return TargetBuilder.forAddress(this, address);
    }

    /**
     * Sets the {@link CounterSupport} with {@link Snmp#setCounterSupport(CounterSupport)} when
     * building the {@link Snmp} instance using {@link #build()}.
     * @param counterSupport
     *    the {@link CounterSupport}, defaults to {@link CounterSupport#getInstance()}.
     * @return
     *    this builder.
     */
    public SnmpBuilder counterSupport(CounterSupport counterSupport) {
        this.counterSupport = counterSupport;
        return this;
    }

    /**
     * Adds the {@link MPv1} security model to {@link Snmp#getMessageDispatcher()}.
     * @return
     *    this builder.
     */
    public SnmpBuilder v1() {
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        return this;
    }

    /**
     * Adds a {@link MPv2c} security model to {@link Snmp#getMessageDispatcher()}.
     * @return
     *    this builder.
     */
    public SnmpBuilder v2c() {
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        return this;
    }

    /**
     * Adds a {@link MPv3} with a randomly created local engine ID {@link Snmp#getMessageDispatcher()} if
     * {@link #usm(SnmpEngineIdProvider, OctetString)} or {@link #tsm(EngineIdProvider, OctetString, boolean)} have not
     * been called yet to set an {@link EngineIdProvider}.
     * <p>
     * CAUTION: Randomly generated engine IDs work fairly well for command generator applications, but SHOULD NOT be
     * used for command responder (i.e. agents). Instead use preferably {@link #v3(OctetString)} or {@link #v3(byte[])}.
     * <p>
     * Make sure to set the {@link SNMP4JSettings#setEnterpriseID(int)} to the company's registered
     * IANA ID before calling this method.
     *
     * @return
     *    this builder.
     */
    public SnmpBuilder v3() {
        if (localEngineID != null) {
            if (engineIdProvider != null) {
                return v3(engineIdProvider.getEngineId(new OctetString(localEngineID)));
            }
            return v3(localEngineID);
        }
        else if (engineIdProvider != null) {
            localEngineID = MPv3.createLocalEngineID();
            return v3(engineIdProvider.getEngineId(new OctetString(localEngineID)));
        }
        return v3(MPv3.createLocalEngineID());
    }

    /**
     * Adds a {@link MPv3} message processing model with a random engine ID based on the supplied ID string.
     * Make sure to set the {@link SNMP4JSettings#setEnterpriseID(int)} to the company's registered
     * IANA ID before calling this method.
     *
     * @param id
     *         an ID string (see RFC 3414) suitable to build an unique local engine ID.
     * @return
     *    this builder
     */
    public SnmpBuilder v3(OctetString id) {
        return v3(MPv3.createLocalEngineID(id));
    }

    /**
     * Adds a {@link MPv3} message processing model with a random engine ID based on the supplied ID string.
     * Make sure to set the {@link SNMP4JSettings#setEnterpriseID(int)} to the company's registered
     * IANA ID before calling this method.
     *
     * @param engineIdProvider
     *         a class that provides the persistently stored engine ID from the previous application execution and
     *         that provides and saves the current boot counter as well as a first time initialized engine ID.
     * @param id
     *         an ID string suitable to build a local engine ID.
     * @return
     *    this builder
     */
    public SnmpBuilder v3(EngineIdProvider engineIdProvider, OctetString id) {
        this.engineIdProvider = engineIdProvider;
        v3(engineIdProvider.getEngineId(new OctetString(MPv3.createLocalEngineID(id))).getValue());
        return this;
    }

    /**
     * Sets the local engine ID for this {@link SnmpBuilder} and creates the message processing model 3 ({@link MPv3})
     * by assigning the {@link SecurityModels} and {@link SecurityProtocols} configured by calls to
     * {@link #usm(SnmpEngineIdProvider, OctetString)} and {@link #tsm(EngineIdProvider, OctetString, boolean)} for
     * example as well as
     * {@link #securityProtocols(SecurityProtocols.SecurityProtocolSet)}.
     * @param localEngineID
     *    the local engine ID of the SNMP entity represented by the {@link Snmp} instance to be built.
     * @return
     *    this builder.
     */
    public SnmpBuilder v3(byte[] localEngineID) {
        this.localEngineID = localEngineID;
        MPv3 mpv3 = new MPv3(localEngineID);
        mpv3.setSecurityModels(securityModels);
        mpv3.setSecurityProtocols(securityProtocols);
        snmp.getMessageDispatcher().addMessageProcessingModel(mpv3);
        return this;
    }

    /**
     * Configures the {@link MultiThreadedMessageDispatcher} as message dispatcher and thereby defines the
     * number of threads in its {@link ThreadPool}.
     * @param numThreads
     *    the number of threads in the {@link MultiThreadedMessageDispatcher}'s  {@link ThreadPool} which must be
     *    greater than 1.
     * @return
     *    this builder.
     */
    public SnmpBuilder threads(int numThreads) {
        MessageDispatcher messageDispatcher = snmp.getMessageDispatcher();
        if (messageDispatcher instanceof MultiThreadedMessageDispatcher) {
            messageDispatcher = ((MultiThreadedMessageDispatcher)messageDispatcher).getDispatcher();
        }
        if (multiThreadedDispatcherPool != null) {
            multiThreadedDispatcherPool.cancel();
        }
        this.multiThreadedDispatcherPool = ThreadPool.create(responderPoolName, numThreads);
        snmp.setMessageDispatcher(new MultiThreadedMessageDispatcher(
                this.multiThreadedDispatcherPool, messageDispatcher));
        return this;
    }

    /**
     * Creates a USM for the specified engine ID and engine boots counter derived from the SNMP engine ID provider
     * given by {@link #v3(EngineIdProvider, OctetString)}. This method requires that either {@link #v3(byte[])}
     * or {@link #v3(EngineIdProvider, OctetString)} have been already called before, otherwise a
     * {@link NullPointerException} will be thrown.
     * @return
     *    this builder.
     */
    public SnmpBuilder usm() {
        if (engineIdProvider != null && engineBootsProvider != null) {
            return usm(engineIdProvider.getEngineId(new OctetString(localEngineID)),
                       engineBootsProvider.updateEngineBoots());
        }
        return usm(new OctetString(((MPv3)
                snmp.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).getLocalEngineID()), 0);
    }

    /**
     * Creates a USM for the specified engine ID and engine boots counter.
     * @param localEngineID
     *         the local engine ID.
     * @param engineBoots
     *         the number of engine boots.
     * @return
     *    this builder.
     */
    public SnmpBuilder usm(OctetString localEngineID, int engineBoots) {
        this.localEngineID = localEngineID.getValue();
        securityModels.addSecurityModel(new USM(securityProtocols, localEngineID, engineBoots));
        return this;
    }

    /**
     * Creates a USM using the specified {@link SnmpEngineIdProvider}.
     * @param snmpEngineIdProvider
     *         the engine ID and boots counter provider, that stores and restores both values according to
     *         RFC 3414, i.e. by increasing engine boots on each application initialization.
     * @param defaultLocalEngineID
     *         the local engine ID if the given {@link SnmpEngineIdProvider} has not stored one yet.
     * @return
     *    this builder.
     */
    public SnmpBuilder usm(SnmpEngineIdProvider snmpEngineIdProvider, OctetString defaultLocalEngineID) {
        this.engineIdProvider = snmpEngineIdProvider;
        this.engineBootsProvider = snmpEngineIdProvider;
        securityModels.addSecurityModel(new USM(securityProtocols, engineIdProvider.getEngineId(defaultLocalEngineID),
                engineBootsProvider.updateEngineBoots()));
        return this;
    }

    /**
     * Creates a Transport Security Model as defined by RFC 5591 and adds it to the built {@link Snmp} instance.
     * @param localEngineID
     *    the engine ID of the SNMP entity using this transport security model. The local engine ID must be globally
     *    unique.
     * @param usePrefix
     *    the snmpTsmConfigurationUsePrefix flag as defined in RFC 5591.
     * @return
     *    this builder.
     */
    public SnmpBuilder tsm(OctetString localEngineID, boolean usePrefix) {
        securityModels.addSecurityModel(new TSM(localEngineID, usePrefix));
        return this;
    }

    /**
     * Creates a Transport Security Model as defined by RFC 5591 and adds it to the built {@link Snmp} instance.
     * @param engineIdProvider
     *    the engine ID of the SNMP entity using this transport security model. The local engine ID must be globally
     *    unique and the {@link EngineIdProvider} is responsible to save the engine ID persistently.
     * @param defaultLocalEngineID
     *    the engine ID to be used and stored persistently if the provided {@code engineIdProvider} cannot provide
     *    an engine ID.
     * @param usePrefix
     *    the snmpTsmConfigurationUsePrefix flag as defined in RFC 5591.
     * @return
     *    this builder.
     */
    public SnmpBuilder tsm(EngineIdProvider engineIdProvider, OctetString defaultLocalEngineID, boolean usePrefix) {
        securityModels.addSecurityModel(new TSM(engineIdProvider.getEngineId(defaultLocalEngineID), usePrefix));
        return this;
    }

    /**
     * Adds a UDP transport mapping ({@link DefaultUdpTransportMapping}) with an operating system chosen local port
     * on all local IP addresses.
     * @return
     *    this builder.
     * @throws IOException
     *    if the socket could not be bound.
     */
    public SnmpBuilder udp() throws IOException {
        TransportMapping<UdpAddress> tm =
                new DefaultUdpTransportMapping(new UdpAddress(new InetSocketAddress(0).getAddress(), 0));
        snmp.getMessageDispatcher().addTransportMapping(tm);
        tm.addTransportListener(snmp.getMessageDispatcher());
        return this;
    }

    /**
     * Adds a set of UDP transport mappings ({@link DefaultUdpTransportMapping}) with the specified local
     * listen addresses
     * @param listenAddresses
     *    the local IPs and ports to listen for incoming UDP messages.
     * @return
     *    this builder.
     * @throws IOException
     *    if one of the sockets could not be bound.
     */
    public SnmpBuilder udp(UdpAddress... listenAddresses) throws IOException {
        for (UdpAddress listenAddress : listenAddresses) {
            UdpTransportMapping udpTransportMapping = new DefaultUdpTransportMapping(listenAddress);
            snmp.getMessageDispatcher().addTransportMapping(udpTransportMapping);
            udpTransportMapping.addTransportListener(snmp.getMessageDispatcher());
        }
        return this;
    }

    /**
     * Add a {@link DefaultTcpTransportMapping} in client mode with an arbitrary local address amd port.
     * @return
     *    this builder.
     * @throws IOException if the local port cannot be bound.
     */
    public SnmpBuilder tcp() throws IOException {
        TransportMapping<TcpAddress> tm =
                new DefaultTcpTransportMapping(new TcpAddress(new InetSocketAddress(0).getAddress(), 0), false);
        snmp.getMessageDispatcher().addTransportMapping(tm);
        tm.addTransportListener(snmp.getMessageDispatcher());
        return this;
    }

    /**
     * Add the {@link DefaultTcpTransportMapping} server mode TCP transport mappings for the specified listen
     * addresses to the {@link Snmp} instance to be built.
     * @param listenAddresses
     *    the local IPs and ports to listen for incoming TCP messages.
     * @return
     *    this builder.
     * @throws IOException if the {@link DefaultTcpTransportMapping} cannot bind all local ports.
     */
    public SnmpBuilder tcp(TcpAddress... listenAddresses) throws IOException {
        for (TcpAddress listenAddress : listenAddresses) {
            TcpTransportMapping<?> tcpTransportMapping = new DefaultTcpTransportMapping(listenAddress, true);
            snmp.getMessageDispatcher().addTransportMapping(tcpTransportMapping);
            tcpTransportMapping.addTransportListener(snmp.getMessageDispatcher());
        }
        return this;
    }

    /**
     * Add a {@link DTLSTM} client mode DTLS transport mapping to the {@link Snmp} instance to be built.
     * @return
     *    this builder.
     * @throws IOException if the {@link DTLSTM} cannot bind the local port.
     */
    public SnmpBuilder dtls() throws IOException {
        DTLSTM dtlstm = new DTLSTM(new DtlsAddress(new InetSocketAddress(0).getAddress(), 0), false);
        snmp.getMessageDispatcher().addTransportMapping(dtlstm);
        dtlstm.addTransportListener(snmp.getMessageDispatcher());
        return this;
    }

    /**
     * Add the {@link DTLSTM} server mode DTLS transport mappings for the specified listen addresses to the {@link Snmp}
     * instance to be built. The DTLS protocol versions to be supported are defined by
     * {@link DTLSTM#DEFAULT_DTLSTM_PROTOCOLS}.
     * @param securityCallback
     *    the callback function to validate X509 certificates of communication peers, see {@link TlsTmSecurityCallback}.
     * @param listenAddresses
     *    the local IPs and ports to listen for incoming DTLS messages.
     * @return
     *    this builder.
     * @throws IOException if the {@link DTLSTM} cannot bind all local ports.
     */
    public SnmpBuilder dtls(TlsTmSecurityCallback<X509Certificate> securityCallback,
                            DtlsAddress... listenAddresses) throws IOException {
        return dtls(securityCallback, null, listenAddresses);
    }

    /**
     * Add the {@link DTLSTM} server mode DTLS transport mappings for the specified listen addresses to the {@link Snmp}
     * instance to be built.
     * @param securityCallback
     *    the callback function to validate X509 certificates of communication peers, see {@link TlsTmSecurityCallback}.
     * @param dtlsProtocolVersions
     *    the DTLS protocol versions to be supported, default is {@link DTLSTM#DEFAULT_DTLSTM_PROTOCOLS}.
     *    That is used when {@code null} is provided.
     * @param listenAddresses
     *    the local IPs and ports to listen for incoming DTLS messages.
     * @return
     *    this builder.
     * @throws IOException if the {@link DTLSTM} cannot bind all local ports.
     */
    public SnmpBuilder dtls(TlsTmSecurityCallback<X509Certificate> securityCallback, String[] dtlsProtocolVersions,
                            DtlsAddress... listenAddresses) throws IOException {
        for (DtlsAddress listenAddress : listenAddresses) {
            DTLSTM dtlsTransportMapping = new DTLSTM(securityCallback, listenAddress, counterSupport, true);
            if (dtlsProtocolVersions != null && dtlsProtocolVersions.length > 0) {
                dtlsTransportMapping.setProtocolVersions(dtlsProtocolVersions);
            }
            snmp.getMessageDispatcher().addTransportMapping(dtlsTransportMapping);
            dtlsTransportMapping.addTransportListener(snmp.getMessageDispatcher());
        }
        return this;
    }

    /**
     * Add a {@link TLSTM} client mode TLS transport mapping to the {@link Snmp} instance to be built.
     * @return
     *    this builder.
     * @throws IOException if the {@link TLSTM} cannot bind the local port.
     */
    public SnmpBuilder tls() throws IOException {
        TLSTM tlstm = new TLSTM(new TlsAddress(new InetSocketAddress(0).getAddress(), 0), false);
        snmp.getMessageDispatcher().addTransportMapping(tlstm);
        tlstm.addTransportListener(snmp.getMessageDispatcher());
        return this;
    }

    /**
     * Add the {@link TLSTM} server mode TLS transport mappings for the specified listen addresses to the {@link Snmp}
     * instance to be built. The TLS protocol versions to be supported are defined by
     * {@link TLSTM#DEFAULT_TLSTM_PROTOCOLS}.
     * @param securityCallback
     *    the callback function to validate X509 certificates of communication peers, see {@link TlsTmSecurityCallback}.
     * @param listenAddresses
     *    the local IPs and ports to listen for incoming TLS messages.
     * @return
     *    this builder.
     * @throws IOException if the {@link TLSTM} cannot bind all local ports.
     */
    public SnmpBuilder tls(TlsTmSecurityCallback<X509Certificate> securityCallback,
                           TlsAddress... listenAddresses) throws IOException {
        return tls(securityCallback, null, listenAddresses);
    }

    /**
     * Add the {@link TLSTM} server mode TLS transport mappings for the specified listen addresses to the {@link Snmp}
     * instance to be built.
     * @param securityCallback
     *    the callback function to validate X509 certificates of communication peers, see {@link TlsTmSecurityCallback}.
     * @param tlsProtocolVersions
     *    the TLS protocol versions to be supported, default is {@link TLSTM#DEFAULT_TLSTM_PROTOCOLS}.
     *    That is used when {@code null} is provided.
     * @param listenAddresses
     *    the local IPs and ports to listen for incoming TLS messages.
     * @return
     *    this builder.
     * @throws IOException if the {@link TLSTM} cannot bind all local ports.
     */
    public SnmpBuilder tls(TlsTmSecurityCallback<X509Certificate> securityCallback, String[] tlsProtocolVersions,
                           TlsAddress... listenAddresses) throws IOException {
        for (TlsAddress listenAddress : listenAddresses) {
            TLSTM tlsTransportMapping = new TLSTM(securityCallback, listenAddress, counterSupport, true);
            if (tlsProtocolVersions != null && tlsProtocolVersions.length > 0) {
                tlsTransportMapping.setProtocolVersions(tlsProtocolVersions);
            }
            snmp.getMessageDispatcher().addTransportMapping(tlsTransportMapping);
            tlsTransportMapping.addTransportListener(snmp.getMessageDispatcher());
        }
        return this;
    }

    /**
     * Specifies which predefined set of {@link SecurityProtocols} should be available for {@link Snmp} session
     * to be built.
     * @param securityProtocolSet
     *    a predefined set of {@link org.snmp4j.security.SecurityProtocol}, default is
     *    {@link org.snmp4j.security.SecurityProtocols.SecurityProtocolSet#defaultSecurity}
     * @return
     *    this builder.
     */
    public SnmpBuilder securityProtocols(SecurityProtocols.SecurityProtocolSet securityProtocolSet) {
        this.securityProtocols.removeAll();
        this.securityProtocols.addPredefinedProtocolSet(securityProtocolSet);
        return this;
    }

    /**
     * Build the {@link Snmp} instance with all the previously called configurations from this fluent builder.
     * @return
     *    a new {@link Snmp} instance, that now starts to {@link Snmp#listen()} for incoming requests/responses.
     * @throws IOException
     *    if the {@link Snmp} instance fails to listen.
     */
    public Snmp build() throws IOException {
        snmp.listen();
        return snmp;
    }
}
