/*_############################################################################
  _## 
  _##  SNMP4J - MessageDispatcherImpl.java  
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
package org.snmp4j;

import java.io.IOException;
import java.util.*;

import org.snmp4j.asn1.*;
import org.snmp4j.event.*;
import org.snmp4j.log.*;
import org.snmp4j.mp.*;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.TsmSecurityStateReference;
import org.snmp4j.smi.*;

import java.nio.ByteBuffer;
import java.util.concurrent.CopyOnWriteArrayList;

import org.snmp4j.transport.TransportType;
import org.snmp4j.transport.UnsupportedAddressClassException;

/**
 * The {@code MessageDispatcherImpl} decodes and dispatches incoming
 * messages using {@link MessageProcessingModel} instances and encodes
 * and sends outgoing messages using an appropriate {@link TransportMapping}
 * instances.
 * <p>
 * The method {@link #processMessage} will be called from a
 * {@code TransportMapping} whereas the method {@link #sendPdu} will be
 * called by the application.
 *
 * @author Frank Fock
 * @version 3.0.3
 * @see Snmp
 * @see TransportMapping
 * @see MessageProcessingModel
 * @see MPv1
 * @see MPv2c
 * @see MPv3
 */
public class MessageDispatcherImpl implements MessageDispatcher {

    private static final LogAdapter logger =
            LogFactory.getLogger(MessageDispatcherImpl.class);

    private List<MessageProcessingModel> mpm = new ArrayList<MessageProcessingModel>(3);
    private final Map<Class<?>, List<TransportMapping<? extends Address>>> receiverTransportMappings =
            Collections.synchronizedMap(new HashMap<>(5));
    private final Map<Class<?>, List<TransportMapping<? extends Address>>> senderTransportMappings =
            Collections.synchronizedMap(new HashMap<>(5));

    private int nextTransactionID = new Random().nextInt(Integer.MAX_VALUE - 2) + 1;
    private transient List<CommandResponder> commandResponderListeners = new CopyOnWriteArrayList<>();
    private transient List<CounterListener> counterListeners = new CopyOnWriteArrayList<>();
    private transient List<AuthenticationFailureListener> authenticationFailureListeners = new CopyOnWriteArrayList<>();

    private boolean checkOutgoingMsg = true;

    /**
     * Default constructor creates a message dispatcher without any associated
     * message processing models.
     */
    public MessageDispatcherImpl() {
    }

    /**
     * Adds a message processing model to this message dispatcher. If a message
     * processing model with the same ID as the supplied one already exists it
     * will not be changed. Please call {@link #removeMessageProcessingModel}
     * before to replace a message processing model.
     *
     * @param model
     *         a MessageProcessingModel instance.
     */
    public synchronized void addMessageProcessingModel(MessageProcessingModel model) {
        while (mpm.size() <= model.getID()) {
            mpm.add(null);
        }
        if (mpm.get(model.getID()) == null) {
            mpm.set(model.getID(), model);
        }
    }

    /**
     * Removes a message processing model from this message dispatcher.
     *
     * @param model
     *         a previously added MessageProcessingModel instance.
     */
    public synchronized void removeMessageProcessingModel(MessageProcessingModel model) {
        mpm.set(model.getID(), null);
    }

    /**
     * Adds a transport mapping. When an outgoing message is processed where
     * no specific transport mapping has been specified, then the
     * message dispatcher will use the transport mapping
     * that supports the supplied address class of the target.
     *
     * @param transport
     *         a TransportMapping instance. If there is already another transport
     *         mapping registered that supports the same address class, then
     *         {@code transport} will be registered but not used for messages
     *         without specific transport mapping.
     */
    public synchronized void addTransportMapping(TransportMapping<?> transport) {
        Set<Class<? extends Address>> supportedAddressClasses = transport.getSupportedAddressClasses();
        for (Class<? extends Address> supportedAddressClass : supportedAddressClasses) {
            if (transport.getSupportedTransportType() == TransportType.any) {
                addTransportMapping(transport, supportedAddressClass, TransportType.receiver);
                addTransportMapping(transport, supportedAddressClass, TransportType.sender);
            }
            else {
                addTransportMapping(transport, supportedAddressClass, transport.getSupportedTransportType());
            }
        }
    }

    private Map<Class<?>, List<TransportMapping<? extends Address>>> getTransportMappings(TransportType transportType) {
        switch (transportType) {
            case receiver: return receiverTransportMappings;
            case sender: return senderTransportMappings;
        }
        logger.error("MessageDispatcher.getTransportMappings called with TransportType.any");
        return receiverTransportMappings;
    }

    private void addTransportMapping(TransportMapping<?> transport, Class<? extends Address> supportedAddressClass,
                                     TransportType transportType) {
        List<TransportMapping<? extends Address>> transports =
                getTransportMappings(transportType).computeIfAbsent(supportedAddressClass, k -> new LinkedList<>());
        transports.add(transport);
    }

    /**
     * Removes a transport mapping.
     *
     * @param transport
     *         a previously added TransportMapping instance.
     *
     * @return the supplied TransportMapping if it has been successfully removed,
     * {@code null}otherwise.
     */
    public TransportMapping<? extends Address> removeTransportMapping(TransportMapping<?> transport) {
        boolean removed = false;
        Set<Class<? extends Address>> supportedAddressClasses = transport.getSupportedAddressClasses();
        for (Class<? extends Address> supportedAddressClass : supportedAddressClasses) {
            if (transport.getSupportedTransportType() == TransportType.any) {
                removed |= removeTransportMapping(transport, supportedAddressClass, TransportType.receiver);
                removed |= removeTransportMapping(transport, supportedAddressClass, TransportType.sender);
            }
            else {
                removed |= removeTransportMapping(transport, supportedAddressClass,
                        transport.getSupportedTransportType());
            }
        }
        if (removed) {
            return transport;
        }
        return null;
    }

    private boolean removeTransportMapping(TransportMapping<?> transport,
                                           Class<? extends Address> supportedAddressClass,
                                           TransportType transportType) {
        Map<Class<?>, List<TransportMapping<? extends Address>>> transportMappings =
                getTransportMappings(transportType);
        List<TransportMapping<? extends Address>> transports =
                transportMappings.computeIfAbsent(supportedAddressClass, k -> new LinkedList<>());
        boolean removed = transports.remove(transport);
        if (transports.isEmpty()) {
            transportMappings.remove(supportedAddressClass);
        }
        return removed;
    }

    /**
     * Gets a collection of all registered transport mappings.
     *
     * @return a Collection instance.
     */
    public Collection<TransportMapping<? extends Address>> getTransportMappings() {
        HashSet<TransportMapping<? extends Address>> l = new HashSet<>();
        synchronized (receiverTransportMappings) {
            for (List<TransportMapping<? extends Address>> tm : receiverTransportMappings.values()) {
                l.addAll(tm);
            }
        }
        synchronized (senderTransportMappings) {
            for (List<TransportMapping<? extends Address>> tm : senderTransportMappings.values()) {
                l.addAll(tm);
            }
        }
        return l;
    }

    public synchronized int getNextRequestID() {
        int nextID = nextTransactionID++;
        if (nextID <= 0) {
            nextID = 1;
            nextTransactionID = 2;
        }
        return nextID;
    }

    protected PduHandle createPduHandle() {
        return new PduHandle(getNextRequestID());
    }

    /**
     * Sends a message using the {@code TransportMapping} that has been
     * assigned for the supplied address type.
     *
     * @param transport
     *         the transport mapping to be used to send the message.
     * @param destAddress
     *         the transport address where to send the message. The
     *         {@code destAddress} must be compatible with the supplied
     *         {@code transport}.
     * @param message
     *         the SNMP message to send.
     * @param tmStateReference
     *         the transport state reference that holds transport state information for this message.
     * @param timeoutMillis
     *         maximum number of milli seconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     *
     * @param <A> an {@link Address} class that is the super class for the addresses supported by this transport mapping.
     * @throws IOException
     *         if an I/O error occurred while sending the message or if there is
     *         no transport mapping defined for the supplied address type.
     */
    @SuppressWarnings("unchecked")
    protected <A extends Address> void sendMessage(TransportMapping<? super A> transport, A destAddress, byte[] message,
                               TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws IOException {

        if (transport != null) {
            if (destAddress instanceof GenericAddress) {
                transport.sendMessage((A)((GenericAddress) destAddress).getAddress(), message, tmStateReference,
                        timeoutMillis, maxRetries);
            } else {
                transport.sendMessage(destAddress, message, tmStateReference, timeoutMillis, maxRetries);
            }
        } else {
            String txt = "No transport mapping for address class: " +
                    destAddress.getClass().getName() + "=" + destAddress;
            logger.error(txt);
            throw new IOException(txt);
        }
    }

    /**
     * Returns a transport mapping that can handle the supplied address. The {@link #getTransportMappings()} known
     * to this message dispatcher are searched for a matching transport mapping using the {@link Address} class
     * hierarchy from the given address class to the root superclass. Each superclass is tested if it is compatible
     * with the supplied address by calling {@link Address#isTransportCompatible(Class)} for that supper class.
     * If that call returns {@code true}, then the first {@link TransportMapping} that returns
     * {@code true} on {@link TransportMapping#isAddressSupported(Address, boolean)} (exactMatch = {@code true})
     * on the given {@code destAddress} is returned.
     * If no such mapping can be found, the list is search again, but with {@code exactMatch} {@code false}.
     * If still no supported mapping can be found, then {@code null} will be returned.
     *
     * @param destAddress
     *         an Address instance.
     *
     * @return a {@code TransportMapping} instance that can be used to sent
     * a SNMP message to {@code destAddress} or {@code null} if
     * such a transport mapping does not exists.
     * @since 1.6
     * @deprecated Use {@link #getTransport(Address, TransportType)} instead to make sure that the returned mapping
     * supports the intended SNMP application type usage (i.e. command/notification generator or command receiver).
     */
    @Override
    @Deprecated
    public <A extends Address> TransportMapping<? super A> getTransport(A destAddress) {
        TransportMapping<? super A> transportMapping = getTransport(destAddress, TransportType.receiver);
        if (transportMapping == null) {
            transportMapping = getTransport(destAddress, TransportType.sender);
        }
        return transportMapping;
    }

    /**
     * Returns a transport mapping that can handle the supplied address. The {@link #getTransportMappings()} known
     * to this message dispatcher are searched for a matching transport mapping using the {@link Address} class
     * hierarchy from the given address class to the root superclass. Each superclass is tested if it is compatible
     * with the supplied address by calling {@link Address#isTransportCompatible(Class)} for that supper class.
     * If that call returns {@code true}, then the first {@link TransportMapping} that returns
     * {@code true} on {@link TransportMapping#isAddressSupported(Address, boolean)} (exactMatch = {@code true})
     * on the given {@code destAddress} is returned.
     * If no such mapping can be found, the list is search again, but with {@code exactMatch} {@code false}.
     * If still no supported mapping can be found, then {@code null} will be returned.
     *
     * @param destAddress
     *         an Address instance.
     * @param transportType
     *         specifies the SNMP application type that will use the returned transport mapping. {@code transportType}
     *         must be either {@link TransportType#receiver} or {@link TransportType#sender}.
     *         If {@link TransportType#any} is provided an {@link IllegalArgumentException} will be thrown.
     *
     * @return a {@code TransportMapping} instance that can be used to sent
     * a SNMP message to {@code destAddress} or {@code null} if
     * such a transport mapping does not exists.
     * @since 3.2.0
     */
    @Override
    @SuppressWarnings("unchecked")
    public <A extends Address> TransportMapping<? super A> getTransport(A destAddress, TransportType transportType) {
        if (transportType == TransportType.any) {
            throw new IllegalArgumentException("TransportType.any not allowed for transport lookup");
        }
        Class<?> addressClass = destAddress.getClass();
        do {
            List<TransportMapping<? extends Address>> l = getTransportMappings(transportType).get(addressClass);
            if ((l != null) && (l.size() > 0)) {
                // first try exact match
                for (TransportMapping<? extends Address> transportMapping :  l) {
                    if (transportMapping.isAddressSupported(destAddress, true)) {
                        return (TransportMapping<? super A>) transportMapping;
                    }
                }
                for (TransportMapping<? extends Address> transportMapping :  l) {
                    if (transportMapping.isAddressSupported(destAddress) &&
                            (destAddress.isTransportCompatible(transportMapping.getSupportedAddressClass()))) {
                        return (TransportMapping<? super A>) transportMapping;
                    }
                }
            }
        }
        while ((addressClass = addressClass.getSuperclass()) != null);
        return null;
    }

    /**
     * Actually decodes and dispatches an incoming SNMP message using the supplied
     * message processing model.
     *
     * @param sourceTransport
     *         a {@link TransportMapping} that matches the incomingAddress type.
     * @param mp
     *         a {@link MessageProcessingModel} to process the message.
     * @param incomingAddress
     *         the {@link Address} from the entity that sent this message.
     * @param wholeMessage
     *         the {@link BERInputStream} containing the SNMP message.
     * @param tmStateReference
     *         the transport model state reference as defined by RFC 5590.
     * @param <A> the {@link Address} type.
     *
     * @throws IOException
     *         if the message cannot be decoded.
     */
    protected <A extends Address> void dispatchMessage(TransportMapping<? super A> sourceTransport,
                                                       MessageProcessingModel mp, A incomingAddress,
                                                       BERInputStream wholeMessage,
                                                       TransportStateReference tmStateReference) throws IOException {
        MutablePDU pdu = new MutablePDU();
        Integer32 messageProcessingModel = new Integer32();
        Integer32 securityModel = new Integer32();
        OctetString securityName = new OctetString();
        Integer32 securityLevel = new Integer32();

        PduHandle handle = createPduHandle();

        Integer32 maxSizeRespPDU =
                new Integer32(sourceTransport.getMaxOutboundMessageSize( ) - MPv3.MAX_HEADER_LENGTH);
        StatusInformation statusInfo = new StatusInformation();
        MutableStateReference<A> mutableStateReference = new MutableStateReference<>();
        // add the transport mapping to the state reference to allow the MP to
        // return REPORTs on the same interface/port the message had been received.
        StateReference<A> stateReference = new StateReference<>();
        stateReference.setTransportMapping(sourceTransport);
        stateReference.setAddress(incomingAddress);
        mutableStateReference.setStateReference(stateReference);

        int status = mp.prepareDataElements(this, incomingAddress, wholeMessage,
                tmStateReference,
                messageProcessingModel, securityModel,
                securityName, securityLevel, pdu,
                handle, maxSizeRespPDU, statusInfo,
                mutableStateReference);
        if (mutableStateReference.getStateReference() != null) {
            // make sure transport mapping is set
            mutableStateReference.getStateReference().setTransportMapping(sourceTransport);
        }
        if (status == SnmpConstants.SNMP_ERROR_SUCCESS) {
            // dispatch it
            CommandResponderEvent<A> e =
                    new CommandResponderEvent<>(this,
                            sourceTransport,
                            incomingAddress,
                            messageProcessingModel.getValue(),
                            securityModel.getValue(),
                            securityName.getValue(),
                            securityLevel.getValue(),
                            handle,
                            pdu.getPdu(),
                            maxSizeRespPDU.getValue(),
                            mutableStateReference.getStateReference());
            e.setTmStateReference(tmStateReference);
            CounterEvent responseTimeEvent = null;
            if (SNMP4JSettings.getSnmp4jStatistics() != SNMP4JSettings.Snmp4jStatistics.none) {
                responseTimeEvent = new CounterEvent(this, SnmpConstants.snmp4jStatsResponseProcessTime,
                        incomingAddress, System.nanoTime());
            }

            fireProcessPdu(e);

            if (responseTimeEvent != null) {
                long increment = (System.nanoTime() - responseTimeEvent.getIncrement()) /
                        SnmpConstants.MILLISECOND_TO_NANOSECOND;
                responseTimeEvent.setIncrement(increment);
                fireIncrementCounter(responseTimeEvent);
            }
        } else {
            switch (status) {
                case SnmpConstants.SNMP_MP_UNSUPPORTED_SECURITY_MODEL:
                case SnmpConstants.SNMPv3_USM_AUTHENTICATION_FAILURE:
                case SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL:
                case SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME:
                case SnmpConstants.SNMPv3_USM_AUTHENTICATION_ERROR:
                case SnmpConstants.SNMPv3_USM_NOT_IN_TIME_WINDOW:
                case SnmpConstants.SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL:
                case SnmpConstants.SNMPv3_USM_UNKNOWN_ENGINEID:
                case SnmpConstants.SNMP_MP_WRONG_USER_NAME:
                case SnmpConstants.SNMPv3_TSM_INADEQUATE_SECURITY_LEVELS:
                case SnmpConstants.SNMP_MP_USM_ERROR: {
                    @SuppressWarnings("unchecked")
                    AuthenticationFailureEvent<A> event =
                            new AuthenticationFailureEvent<>(this, incomingAddress,
                                    (TransportMapping<? super A>) sourceTransport, status, wholeMessage);
                    fireAuthenticationFailure(event);
                    break;
                }
            }
            if (logger.isInfoEnabled()) {
                logger.info("Dispatching message canceled due to security issue: statusInfo="
                        + statusInfo + ", status=" + status + ",tmStateReference="+tmStateReference);
            }
        }
    }

    public <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport, A incomingAddress,
                                                   ByteBuffer wholeMessage, TransportStateReference tmStateReference) {
        processMessage(sourceTransport, incomingAddress, new BERInputStream(wholeMessage), tmStateReference);
    }

    public <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport, A incomingAddress,
                                                   BERInputStream wholeMessage,
                                                   TransportStateReference tmStateReference) {
        fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpInPkts));
        if (!wholeMessage.markSupported()) {
            String txt = "Message stream must support marks";
            logger.error(txt);
            throw new IllegalArgumentException(txt);
        }
        try {
            wholeMessage.mark(16);
            BER.MutableByte type = new BER.MutableByte();
            // decode header but do not check length here, because we do only decode
            // the first 16 bytes.
            BER.decodeHeader(wholeMessage, type, false);
            if (type.getValue() != BER.SEQUENCE) {
                logger.error("ASN.1 parse error (message is not a sequence)");
                CounterEvent event = new CounterEvent(this,
                        SnmpConstants.snmpInASNParseErrs);
                fireIncrementCounter(event);
            }
            Integer32 version = new Integer32();
            version.decodeBER(wholeMessage);
            MessageProcessingModel mp = getMessageProcessingModel(version.getValue());
            if (mp == null) {
                logger.warn("SNMP version " + version + " is not supported");
                CounterEvent event = new CounterEvent(this,
                        SnmpConstants.snmpInBadVersions);
                fireIncrementCounter(event);
            } else {
                // reset it
                wholeMessage.reset();
                // dispatch it
                dispatchMessage(sourceTransport, mp, incomingAddress, wholeMessage, tmStateReference);
            }
        } catch (IOException iox) {
            if (logger.isDebugEnabled()) {
                iox.printStackTrace();
            }
            logger.warn(iox);
            CounterEvent event =
                    new CounterEvent(this, SnmpConstants.snmpInvalidMsgs);
            fireIncrementCounter(event);
        } catch (Exception ex) {
            logger.error(ex);
            if (logger.isDebugEnabled()) {
                ex.printStackTrace();
            }
            if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                throw new RuntimeException(ex);
            }
        } catch (OutOfMemoryError oex) {
            logger.error(oex);
            if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                throw oex;
            }
        }
    }

    @Override
    public <A extends Address> PduHandle sendPdu(Target<A> target, PDU pdu, boolean expectResponse)
            throws MessageException {
        return sendPdu(null, target, pdu, expectResponse);
    }

    public <A extends Address> PduHandle sendPdu(TransportMapping<? super A> transport, Target<A> target, PDU pdu,
                                                 boolean expectResponse, PduHandleCallback<PDU> pduHandleCallback)
            throws MessageException {
        int messageProcessingModel = target.getVersion();
        A transportAddress = target.getAddress();
        int securityModel = target.getSecurityModel();
        int securityLevel = target.getSecurityLevel();
        try {
            byte[] securityName = OctetString.toByteArray(target.getSecurityName());
            MessageProcessingModel mp = getMessageProcessingModel(messageProcessingModel);
            if (mp == null) {
                String msg = "Unsupported message processing model: " + messageProcessingModel;
                logger.error(msg);
                throw new MessageException(msg, SnmpConstants.SNMP_MD_UNSUPPORTED_MP_MODEL);
            }
            if (!mp.isProtocolVersionSupported(messageProcessingModel)) {
                String msg = "SNMP version " + messageProcessingModel +
                        " is not supported " +
                        "by message processing model " +
                        messageProcessingModel;
                logger.error(msg);
                throw new MessageException(msg, SnmpConstants.SNMP_MD_UNSUPPORTED_SNMP_VERSION);
            }
            if (transport == null) {
                transport = getTransport(transportAddress,
                        (pdu.isResponsePdu()) ? TransportType.receiver : TransportType.sender);
            }
            if (transport == null) {
                String msg = "Unsupported address class (transport mapping is null): " +
                        transportAddress.getClass().getName();
                logger.error(msg);
                throw new UnsupportedAddressClassException(msg, transportAddress.getClass());
            } else if (pdu.isConfirmedPdu()) {
                checkListening4ConfirmedPDU(pdu, target.getAddress(), transport);
            }

            // check if contextEngineID discovery is needed


            // check PDU type
            checkOutgoingMsg(transportAddress, messageProcessingModel, pdu);

            // if request ID is == 0 then create one here, otherwise use the request
            // ID because it may be a resent request.
            PduHandle pduHandle;
            Integer32 reqID = pdu.getRequestID();
            if (((reqID == null) || (reqID.getValue() == 0)) &&
                    (pdu.getType() != PDU.RESPONSE)) {
                pduHandle = createPduHandle();
            } else {
                pduHandle = new PduHandle(pdu.getRequestID().getValue());
            }

            // assign request ID
            if (pdu.getType() != PDU.V1TRAP) {
                pdu.setRequestID(new Integer32(pduHandle.getTransactionID()));
            }
            TransportStateReference tmStateReference =
                    new TransportStateReference(transport,
                            transportAddress,
                            OctetString.fromByteArray(securityName),
                            SecurityLevel.get(securityLevel),
                            SecurityLevel.undefined,
                            false, null, target);

            if (pdu.isConfirmedPdu()) {
                configureAuthoritativeEngineID(target, mp);
            }
            BEROutputStream outgoingMessage = new BEROutputStream();
            int status = mp.prepareOutgoingMessage(transportAddress,
                    transport.getMaxOutboundMessageSize(),
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    pdu,
                    expectResponse,
                    pduHandle,
                    outgoingMessage,
                    tmStateReference);

            if (status == SnmpConstants.SNMP_ERROR_SUCCESS) {
                // inform callback about PDU new handle
                if (pduHandleCallback != null) {
                    pduHandleCallback.pduHandleAssigned(pduHandle, pdu);
                }
                byte[] messageBytes = outgoingMessage.getBuffer().array();
                sendMessage(transport, transportAddress, messageBytes, tmStateReference,
                        target.getTimeout(), target.getRetries());
            } else {
                String msg = "Message processing model " + mp.getID() + " returned error: " +
                        SnmpConstants.mpErrorMessage(status);
                logger.error(msg);
                throw new MessageException(msg, status);
            }
            return pduHandle;
        } catch (IndexOutOfBoundsException iobex) {
            String msg = "Unsupported message processing model: " + messageProcessingModel;
            logger.error(msg, iobex);
            throw new MessageException(msg, SnmpConstants.SNMP_MD_UNSUPPORTED_MP_MODEL, iobex);
        } catch (MessageException mex) {
            if (logger.isDebugEnabled()) {
                mex.printStackTrace();
            }
            throw mex;
        } catch (IOException iox) {
            logger.error(iox.getMessage(), iox);
            if (logger.isDebugEnabled()) {
                iox.printStackTrace();
            }
            throw new MessageException(iox.getMessage(), SnmpConstants.SNMP_MD_ERROR, iox);
        }
    }

    protected void configureAuthoritativeEngineID(Target<?> target, MessageProcessingModel mp) {
        if ((target instanceof UserTarget) && (mp instanceof MPv3)) {
            UserTarget<?> userTarget = (UserTarget) target;
            if ((userTarget.getAuthoritativeEngineID() != null) && (userTarget.getAuthoritativeEngineID().length > 0)) {
                ((MPv3) mp).addEngineID(target.getAddress(), new OctetString(userTarget.getAuthoritativeEngineID()));
            }
        }
    }

    private static void checkListening4ConfirmedPDU(PDU pdu, Address target,
                                                    TransportMapping<?> transport) {
        if ((transport != null) && (!transport.isListening())) {
            logger.warn("Sending confirmed PDU " + pdu + " to target " + target +
                    " although transport mapping " + transport +
                    " is not listening for a response");
        }
    }

    /**
     * Checks outgoing messages for consistency between PDU and target used.
     *
     * @param transportAddress
     *         the target address.
     * @param messageProcessingModel
     *         the message processing model to be used.
     * @param pdu
     *         the PDU to be sent.
     *
     * @throws MessageException
     *         if unrecoverable inconsistencies have been detected.
     */
    protected void checkOutgoingMsg(Address transportAddress,
                                    int messageProcessingModel, PDU pdu)
            throws MessageException {
        if (checkOutgoingMsg) {
            if (messageProcessingModel == MessageProcessingModel.MPv1 || SNMP4JSettings.isNoGetBulk()) {
                if (pdu.getType() == PDU.GETBULK) {
                    if (messageProcessingModel == MessageProcessingModel.MPv1) {
                        logger.warn("Converting GETBULK PDU to GETNEXT for SNMPv1 target: " + transportAddress);
                    } else {
                        logger.info("Converting GETBULK PDU to GETNEXT for target: " + transportAddress);
                    }
                    pdu.setType(PDU.GETNEXT);
                    if (!(pdu instanceof PDUv1)) {
                        pdu.setMaxRepetitions(0);
                        pdu.setNonRepeaters(0);
                    }
                }
            }
        }
    }

    public <A extends Address> int returnResponsePdu(int messageProcessingModel, int securityModel, byte[] securityName,
                                                     int securityLevel, PDU pdu, int maxSizeResponseScopedPDU,
                                                     StateReference<A> stateReference,
                                                     StatusInformation statusInformation)
            throws MessageException {
        try {
            MessageProcessingModel mp = getMessageProcessingModel(messageProcessingModel);
            if (mp == null) {
                throw new MessageException("Unsupported message processing model: "
                        + messageProcessingModel, SnmpConstants.SNMP_MD_UNSUPPORTED_MP_MODEL);
            }
            TransportMapping<? super A> transport =
                    (stateReference != null ? stateReference.getTransportMapping() : null);
            if (transport == null && stateReference != null) {
                transport = getTransport(stateReference.getAddress(), TransportType.receiver);
            }
            if (transport == null) {
                throw new MessageException("Unsupported address class (transport mapping is null): " +
                        ((stateReference != null) ? stateReference.getAddress().getClass().getName() : "stateReference is null"),
                        SnmpConstants.SNMP_MD_UNSUPPORTED_ADDRESS_CLASS);
            }
            BEROutputStream outgoingMessage = new BEROutputStream();
            int status = mp.prepareResponseMessage(messageProcessingModel,
                    transport.getMaxInboundMessageSize(),
                    securityModel,
                    securityName, securityLevel, pdu,
                    maxSizeResponseScopedPDU,
                    stateReference,
                    statusInformation,
                    outgoingMessage);
            if (status == SnmpConstants.SNMP_MP_OK) {
                TransportStateReference tmStateReference = null;
                if (stateReference.getSecurityStateReference() instanceof TsmSecurityStateReference) {
                    tmStateReference = ((TsmSecurityStateReference)
                            stateReference.getSecurityStateReference()).getTmStateReference();
                }
                sendMessage(transport,
                        stateReference.getAddress(),
                        outgoingMessage.getBuffer().array(),
                        tmStateReference, 0, 0);
            }
            return status;
        } catch (ArrayIndexOutOfBoundsException aex) {
            throw new MessageException("Unsupported message processing model: "
                    + messageProcessingModel, SnmpConstants.SNMP_MD_UNSUPPORTED_MP_MODEL, aex);
        } catch (IOException iox) {
            throw new MessageException(iox.getMessage(), SnmpConstants.SNMP_MD_ERROR, iox);
        }
    }

    public void releaseStateReference(int messageProcessingModel, PduHandle pduHandle) {
        MessageProcessingModel mp = getMessageProcessingModel(messageProcessingModel);
        if (mp == null) {
            throw new IllegalArgumentException("Unsupported message processing model: " +
                    messageProcessingModel);
        }
        mp.releaseStateReference(pduHandle);
    }

    public void removeCommandResponder(CommandResponder l) {
        commandResponderListeners.remove(l);
    }

    public void addCommandResponder(CommandResponder l) {
        if (!commandResponderListeners.contains(l)) {
            commandResponderListeners.add(l);
        }
    }

    /**
     * Fires a {@code CommandResponderEvent}. Listeners are called
     * in order of their registration  until a listener has processed the
     * PDU successfully.
     *
     * @param e
     *         a {@code CommandResponderEvent} event.
     */
    protected void fireProcessPdu(CommandResponderEvent<?> e) {
        List<CommandResponder> listeners = commandResponderListeners;
        for (CommandResponder listener : listeners) {
            listener.processPdu(e);
            // if event is marked as processed the event is not forwarded to
            // remaining listeners
            if (e.isProcessed()) {
                return;
            }
        }
    }

    /**
     * Gets the {@link MessageProcessingModel} for the supplied message
     * processing model ID.
     *
     * @param messageProcessingModel
     *         a message processing model ID
     *         (see {@link MessageProcessingModel#getID()}).
     *
     * @return a MessageProcessingModel instance if the ID is known, otherwise
     * {@code null}
     */
    public MessageProcessingModel getMessageProcessingModel(int messageProcessingModel) {
        try {
            return mpm.get(messageProcessingModel);
        } catch (IndexOutOfBoundsException iobex) {
            return null;
        }
    }

    /**
     * Removes a {@code CounterListener}.
     *
     * @param counterListener
     *         a previously added {@code CounterListener}.
     */
    public synchronized CounterListener removeCounterListener(CounterListener counterListener) {
        return counterListeners.remove(counterListener) ? counterListener : null;
    }

    /**
     * Adds a {@code CounterListener}.
     *
     * @param counterListener
     *         a {@code CounterListener} that will be informed when a counter
     *         needs to incremented.
     */
    public void addCounterListener(CounterListener counterListener) {
        if (!counterListeners.contains(counterListener)) {
            counterListeners.add(counterListener);
        }
    }

    /**
     * Fires a counter incrementation event.
     *
     * @param event
     *         the {@code CounterEvent} containing the OID of the counter
     *         that needs to be incremented.
     */
    protected void fireIncrementCounter(CounterEvent event) {
        for (CounterListener cl : counterListeners) {
            cl.incrementCounter(event);
        }
    }

    /**
     * Enables or disables the consistency checks for outgoing messages.
     * If the checks are enabled, then GETBULK messages sent to SNMPv1
     * targets will be converted to GETNEXT messages.
     * <p>
     * In general, if an automatically conversion is not possible, an
     * error is thrown when such a message is to be sent.
     * <p>
     * The default is consistency checks enabled.
     *
     * @param checkOutgoingMsg
     *         if {@code true} outgoing messages are checked for consistency.
     *         Currently, only the PDU type will be checked against the used SNMP
     *         version. If {@code false}, no checks will be performed.
     */
    public void setCheckOutgoingMsg(boolean checkOutgoingMsg) {
        this.checkOutgoingMsg = checkOutgoingMsg;
    }

    /**
     * Returns whether consistency checks for outgoing messages are activated.
     *
     * @return if {@code true} outgoing messages are checked for consistency.
     * If {@code false}, no checks are performed.
     */
    public boolean isCheckOutgoingMsg() {
        return checkOutgoingMsg;
    }

    /**
     * Adds a listener for authentication failure events caused by unauthenticated
     * incoming messages.
     *
     * @param l
     *         the {@code AuthenticationFailureListener} to add.
     *
     * @since 1.5
     */
    public synchronized void addAuthenticationFailureListener(AuthenticationFailureListener l) {
        if (!authenticationFailureListeners.contains(l)) {
            authenticationFailureListeners.add(l);
        }
    }

    /**
     * Removes an {@code AuthenticationFailureListener}.
     *
     * @param l
     *         the {@code AuthenticationFailureListener} to remove.
     */
    public synchronized void removeAuthenticationFailureListener(
            AuthenticationFailureListener l) {
        authenticationFailureListeners.remove(l);
    }

    /**
     * Fires an {@code AuthenticationFailureEvent} to all registered
     * listeners.
     *
     * @param event
     *         the event to fire.
     */
    protected void fireAuthenticationFailure(AuthenticationFailureEvent<?> event) {
        List<AuthenticationFailureListener> listeners = authenticationFailureListeners;
        for (AuthenticationFailureListener listener : listeners) {
            listener.authenticationFailure(event);
        }
    }

    public <A extends Address> PduHandle sendPdu(TransportMapping<? super A> transportMapping, Target<A> target,
                                                 PDU pdu, boolean expectResponse) throws MessageException {
        return sendPdu(transportMapping, target, pdu, expectResponse, null);
    }

    private class TransportMappingKey {
        private TransportType transportType;
        private Class<?> rootAddressClass;

        public TransportMappingKey(TransportType transportType, Class<?> rootAddressClass) {
            this.transportType = transportType;
            this.rootAddressClass = rootAddressClass;
        }

        public TransportType getTransportType() {
            return transportType;
        }

        public Class<?> getRootAddressClass() {
            return rootAddressClass;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            TransportMappingKey that = (TransportMappingKey) o;

            if (getTransportType() != that.getTransportType()) return false;
            return getRootAddressClass().equals(that.getRootAddressClass());

        }

        @Override
        public int hashCode() {
            int result = getTransportType().hashCode();
            result = 31 * result + getRootAddressClass().hashCode();
            return result;
        }

        @Override
        public String toString() {
            return "TransportMappingKey{" +
                    "transportType=" + transportType +
                    ", rootAddressClass=" + rootAddressClass +
                    '}';
        }
    }
}

