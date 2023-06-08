/*_############################################################################
  _## 
  _##  SNMP4J - TransportMapping.java  
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

import java.io.Closeable;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.snmp4j.smi.Address;
import org.snmp4j.transport.TransportListener;
import org.snmp4j.transport.TransportType;

/**
 * The {@code TransportMapping} defines the common interface for SNMP
 * transport mappings. A transport mapping can only support a single
 * transport protocol.
 * @param <A> an {@link Address} class that is the super class for the addresses supported by this transport mapping.
 *
 * @author Frank Fock
 * @version 3.2.0
 */
public interface TransportMapping<A extends Address> extends Closeable {

    /**
     * Gets the primary {@code Address} class that is supported by this transport mapping.
     *
     * @return a subclass of {@link Address}.
     */
    Class<? extends Address> getSupportedAddressClass();

    /**
     * Return all {@code Address} classes supported by this transport mapping. For example, if
     * {@link org.snmp4j.smi.DtlsAddress} is supported as primary address class this will also return
     * {@link org.snmp4j.smi.UdpAddress} as secondary supported address class.
     * @return
     *    a set of address classes with at least one element (see {@link #getSupportedAddressClass()}.
     */
    default Set<Class<? extends Address>> getSupportedAddressClasses() {
        return Collections.singleton(getSupportedAddressClass());
    }

    /**
     * Checks if the provided address can be used with this transport mapping.
     * @param addressType
     *         an {@code Address} instance representing a target address.
     * @return {@code true} if the specified address can be used as target address with this {@link TransportMapping}.
     * @since 3.1.0
     */
    default boolean isAddressSupported(Address addressType) {
        return isAddressSupported(addressType, false);
    }

    /**
     * Checks if the provided address can be used with this transport mapping.
     * @param addressType
     *         an {@code Address} instance representing a target address.
     * @param exactMatch
     *         if {@code true} this method returns {@code true} only if the given addressType's class equals the
     *         address class returned by {@link #getSupportedAddressClass()}.
     * @return {@code true} if the specified address can be used as target address with this {@link TransportMapping}.
     * @since 3.2.1
     */
    default boolean isAddressSupported(Address addressType, boolean exactMatch) {
        if (exactMatch) {
            return getSupportedAddressClass().equals(addressType.getClass());
        }
        for (Class<? extends Address> addressClass : getSupportedAddressClasses()) {
            if (addressClass.isInstance(addressType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the address that represents the actual incoming address this transport
     * mapping uses to listen for incoming packets.
     *
     * @return the address for incoming packets or {@code null} this transport
     * mapping is not configured to listen for incoming packets.
     * @since 1.6
     */
    A getListenAddress();

    /**
     * Sends a message to the supplied address using this transport.
     *
     * @param address
     *         an {@code Address} instance denoting the target address.
     * @param message
     *         the whole message as an array of bytes.
     * @param tmStateReference
     *         the (optional) transport model state reference as defined by
     *         RFC 5590 section 6.1.
     * @param timeoutMillis
     *         maximum number of milli seconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     *
     * @throws IOException
     *         if any underlying IO operation fails.
     */
    void sendMessage(A address, byte[] message,
                     TransportStateReference tmStateReference, long timeoutMillis, int maxRetries) throws IOException;

    /**
     * Adds a transport listener to the transport. Normally, at least one
     * transport listener needs to be added to process incoming messages.
     *
     * @param transportListener
     *         a {@code TransportListener} instance.
     *
     * @since 1.6
     */
    void addTransportListener(TransportListener transportListener);

    /**
     * Removes a transport listener. Incoming messages will no longer be
     * propagated to the supplied {@code TransportListener}.
     *
     * @param transportListener
     *         a {@code TransportListener} instance.
     *
     * @since 1.6
     */
    void removeTransportListener(TransportListener transportListener);

    /**
     * Closes the transport an releases all bound resources synchronously.
     *
     * @throws IOException
     *         if any IO operation for the close fails.
     */
    @Override
    void close() throws IOException;

    /**
     * Listen for incoming messages. For connection oriented transports, this
     * method needs to be called before {@link #sendMessage} is called for the
     * first time.
     *
     * @throws IOException
     *         if an IO operation exception occurs while starting the listener.
     */
    void listen() throws IOException;

    /**
     * Returns {@code true} if the transport mapping is listening for
     * incoming messages. For connection oriented transport mappings this
     * is a prerequisite to be able to send SNMP messages. For connectionless
     * transport mappings it is a prerequisite to be able to receive responses.
     *
     * @return {@code true} if this transport mapping is listening for messages.
     * @since 1.1
     */
    boolean isListening();

    /**
     * Gets the maximum length of an incoming message that can be successfully
     * processed by this transport mapping implementation.
     *
     * @return an integer &gt; 484.
     */
    int getMaxInboundMessageSize();

    /**
     * Gets the maximum length of an outgoing message that can be successfully
     * send by this transport mapping implementation. By default, {@link #getMaxInboundMessageSize()} is returned.
     *
     * @return an integer &gt; 484.
     * @since 3.7.4
     */
    default int getMaxOutboundMessageSize() {
        return getMaxInboundMessageSize();
    }

    /**
     * Gets the {@link TransportType} this {@code TransportMapping} supports.
     * @return {@link TransportType#receiver} if command responder applications are supported
     * and {@link TransportType#sender} if command generator and notification generator applications are supported and
     * {@link TransportType#any} if any type of applications are supported with this instance.
     * @since 3.2.0
     */
    default TransportType getSupportedTransportType() {
        return TransportType.any;
    }
}

