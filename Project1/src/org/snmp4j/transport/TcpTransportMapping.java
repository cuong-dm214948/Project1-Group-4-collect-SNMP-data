/*_############################################################################
  _## 
  _##  SNMP4J - TcpTransportMapping.java  
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

import java.io.IOException;

import org.snmp4j.TransportStateReference;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.TcpAddress;

import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogAdapter;

/**
 * The {@code TcpTransportMapping} is the abstract base class for
 * TCP transport mappings.
 * @param <S> defines the type of {@link AbstractSocketEntry} used by this transport mapping.
 *
 * @author Frank Fock
 * @version 3.7.0
 */
public abstract class TcpTransportMapping<S extends AbstractSocketEntry<TcpAddress>>
        extends AbstractConnectionOrientedTransportMapping<TcpAddress, S>
        implements ConnectionOrientedTransportMapping<TcpAddress> {

    private static final LogAdapter logger = LogFactory.getLogger(TcpTransportMapping.class);

    protected TcpAddress tcpAddress;

    /**
     * Enable or disable automatic (re)opening the communication socket when sending a message
     */
    protected boolean openSocketOnSending = true;

    public TcpTransportMapping(TcpAddress tcpAddress) {
        this.tcpAddress = tcpAddress;
    }

    public Class<? extends Address> getSupportedAddressClass() {
        return TcpAddress.class;
    }

    /**
     * Returns the transport address that is used by this transport mapping for
     * sending and receiving messages.
     *
     * @return the {@code Address} used by this transport mapping. The returned
     * instance must not be modified!
     * @deprecated Use {@link #getListenAddress()} instead.
     */
    public TcpAddress getAddress() {
        return tcpAddress;
    }

    @Override
    public TcpAddress getListenAddress() {
        return tcpAddress;
    }

    public abstract void sendMessage(TcpAddress address, byte[] message,
                                     TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws IOException;

    /**
     * If {@code true} and method {@link #listen()} has not been called yet or the connection has been closed or reset,
     * then {@link #listen()} will be called to open the communication socket when a message is being sent using
     * {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)}.
     *
     * @return
     *     {@code true} if {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)} will ensure that
     *     a server socket is there for receiving responses, {@code false} otherwise.
     * @since 3.4.4
     */
    public boolean isOpenSocketOnSending() {
        return openSocketOnSending;
    }

    /**
     * Activate or deactivate auto {@link #listen()} when
     * {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)} is called but there is no listening
     * socket.
     *
     * @param openSocketOnSending
     *     {@code true} if {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)} should ensure
     *     that server socket is available for communication, {@code false} if {@link #listen()} must be called
     *     explicitly.
     * @since 3.4.4
     */
    public void setOpenSocketOnSending(boolean openSocketOnSending) {
        this.openSocketOnSending = openSocketOnSending;
    }

    public abstract void listen() throws IOException;

    /**
     * Returns the {@code MessageLengthDecoder} used by this transport
     * mapping.
     *
     * @return a MessageLengthDecoder instance.
     * @since 1.7
     */
    public abstract MessageLengthDecoder getMessageLengthDecoder();

    /**
     * Sets the {@code MessageLengthDecoder} that decodes the total
     * message length from the header of a message.
     *
     * @param messageLengthDecoder
     *         a MessageLengthDecoder instance.
     *
     * @since 1.7
     */
    public abstract void setMessageLengthDecoder(MessageLengthDecoder messageLengthDecoder);

}
