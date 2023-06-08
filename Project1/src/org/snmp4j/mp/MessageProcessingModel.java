/*_############################################################################
  _## 
  _##  SNMP4J - MessageProcessingModel.java  
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
package org.snmp4j.mp;

import java.io.IOException;

import org.snmp4j.*;
import org.snmp4j.smi.*;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.MutablePDU;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.asn1.BEROutputStream;
// needed by JavaDoc:


/**
 * The {@code MessageProcessingModel} interface defines common methods to all SNMP message processing models.
 * <p>Note: The read counter of the {@link BERInputStream} parameters in this
 * interface should not be reset while those methods are executed.
 *
 * @author Frank Fock
 * @version 3.1.0
 */
public interface MessageProcessingModel {

    int MPv1 = 0;
    int MPv2c = 1;
    int MPv2u = 2;
    int MPv3 = 3;

    /**
     * Gets the numerical ID of the message processing model as defined by the constants in this interface or by an
     * appropriate constant in the class implementing this interface.
     *
     * @return a positive integer value.
     */
    int getID();

    /**
     * Prepares an outgoing message as defined in RFC3412 §7.1.
     *
     * @param transportAddress
     *         the destination transport {@code Address}.
     * @param maxMsgSize
     *         the maximum message size the transport mapping for the destination address is capable of.
     * @param messageProcessingModel
     *         the {@link MessageProcessingModel} ID (typically, the SNMP version).
     * @param securityModel
     *         the security model ID (see {@link org.snmp4j.security.SecurityModel}) to use.
     * @param securityName
     *         the principal on behalf the message is to be sent.
     * @param securityLevel
     *         the level of security requested (see {@link org.snmp4j.security.SecurityLevel}).
     * @param pdu
     *         the {@code PDU} to send. For a SNMPv1 trap {@code pdu} has to be a {@link org.snmp4j.PDUv1}
     *         instance, for SNMPv3 messages it has to be a {@link org.snmp4j.ScopedPDU} instance.
     * @param expectResponse
     *         indicates if a message expects a response. This has to be
     *         {@code true} for confirmed class PDUs and {@code false}
     *         otherwise.
     * @param sendPduHandle
     *         the {@code PduHandle} that uniquely identifies the sent message.
     * @param outgoingMessage
     *         returns the message to send.
     * @param tmStateReference
     *         the transport model state reference as defined by RFC 5590.
     * @param <A> the target {@link Address} type.
     *
     * @return the status of the message preparation. {@link SnmpConstants#SNMP_MP_OK} is returned if on success,
     * otherwise any of the
     * {@code SnmpConstants.SNMP_MP_*} values may be returned.
     * @throws IOException
     *         if the supplied PDU could not be encoded to the
     *         {@code outgoingMessage}
     */
    <A extends Address> int prepareOutgoingMessage(A transportAddress, int maxMsgSize, int messageProcessingModel,
                                                   int securityModel, byte[] securityName, int securityLevel, PDU pdu,
                                                   boolean expectResponse, PduHandle sendPduHandle,
                                                   BEROutputStream outgoingMessage,
                                                   TransportStateReference tmStateReference)
            throws IOException;

    /**
     * Prepares a response message as defined in RFC3412 §7.1.
     *
     * @param messageProcessingModel
     *         int the {@link org.snmp4j.mp.MessageProcessingModel} ID (typically, the SNMP version).
     * @param maxMsgSize
     *         the maximum message size the transport mapping for the destination address is capable of.
     * @param securityModel
     *         the security model ID (see {@link org.snmp4j.security.SecurityModel}) to use.
     * @param securityName
     *         the principal on behalf the message is to be sent.
     * @param securityLevel
     *         the level of security requested (see {@link org.snmp4j.security.SecurityLevel}).
     * @param pdu
     *         the {@code PDU} to send. For a SNMPv1 trap {@code pdu} has to be a {@link org.snmp4j.PDUv1}
     *         instance, for SNMPv3 messages it has to be a {@link org.snmp4j.ScopedPDU} instance.
     * @param maxSizeResponseScopedPDU
     *         the maximum size of the scoped PDU the sender (of the request) can accept.
     * @param stateReference
     *         reference to state information presented with the request.
     * @param statusInformation
     *         returns success or error indication. When an error occured, the error counter OID and value are
     *         included.
     * @param outgoingMessage
     *         returns the message to send.
     * @param <A> the target {@link Address} type.
     *
     * @return the status of the message preparation. {@link SnmpConstants#SNMP_MP_OK} is returned if on success,
     * otherwise any of the
     * {@code SnmpConstants.SNMP_MP_*} values may be returned.
     * @throws IOException
     *         if an internal error or a resource exception occured.
     */
    <A extends Address> int prepareResponseMessage(int messageProcessingModel, int maxMsgSize, int securityModel,
                                                   byte[] securityName, int securityLevel, PDU pdu,
                                                   int maxSizeResponseScopedPDU, StateReference<A> stateReference,
                                                   StatusInformation statusInformation, BEROutputStream outgoingMessage)
            throws IOException;

    /**
     * Prepare data elements from an incoming SNMP message as described in RFC3412 §7.2.
     *
     * @param messageDispatcher
     *         the {@code MessageDispatcher} instance to be used to send reports. Thus,
     *         {@code messageDispatcher} is typically the calling module.
     * @param transportAddress
     *         the origin transport address.
     * @param wholeMsg
     *         the whole message as received from the network.
     * @param tmStateReference
     *         the transport model state reference as defined by RFC 5590.
     * @param messageProcessingModel
     *         returns the message processing model (typically the SNMP version).
     * @param securityModel
     *         returns the security model ID (see {@link org.snmp4j.security.SecurityModel}.
     * @param securityName
     *         returns the principal.
     * @param securityLevel
     *         returns the requested security level (see {@link org.snmp4j.security.SecurityLevel}).
     * @param pdu
     *         returns SNMP protocol data unit (the payload of the received message).
     * @param sendPduHandle
     *         returns the handle to match request.
     * @param maxSizeResponseScopedPDU
     *         returns the maximum size of the scoped PDU the sender can accept.
     * @param statusInformation
     *         returns success or error indication. When an error occured, the error counter OID and value are
     *         included.
     * @param mutableStateReference
     *         returns the state reference to be used for a possible response. On input the stateReference may contain
     *         information about the transport mapping of the incoming request. This allows the
     *         {@code MessageProcessingModel} to send reports over the same
     *         transport as it received them.
     * @param <A> the target {@link Address} type.
     *
     * @return int the status of the message preparation. {@link SnmpConstants#SNMP_MP_OK} is returned on success,
     * otherwise any of the
     * {@code SnmpConstants.SNMP_MP_*} values may be returned.
     * @throws IOException
     *         if the decoding of the message failed.
     */
    <A extends Address> int prepareDataElements(MessageDispatcher messageDispatcher, A transportAddress,
                                                BERInputStream wholeMsg, TransportStateReference tmStateReference,
                                                Integer32 messageProcessingModel, Integer32 securityModel,
                                                OctetString securityName, Integer32 securityLevel, MutablePDU pdu,
                                                PduHandle sendPduHandle, Integer32 maxSizeResponseScopedPDU,
                                                StatusInformation statusInformation,
                                                MutableStateReference<A> mutableStateReference)
            throws IOException;

    /**
     * Checks whether the supplied SNMP protocol version is supported by this message processing model.
     *
     * @param snmpProtocolVersion
     *         the SNMP protocol version.
     *
     * @return {@code true} if the supplied SNMP protocol is supported,
     * {@code false} otherwise.
     */
    boolean isProtocolVersionSupported(int snmpProtocolVersion);

    /**
     * Release the state reference associated with the supplied
     * {@code PduHandle}.
     *
     * @param pduHandle
     *         a {@code PduHandle}.
     */
    void releaseStateReference(PduHandle pduHandle);
}

