/*_############################################################################
  _## 
  _##  SNMP4J - AbstractSocketEntry.java  
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

import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.TcpAddress;

import java.net.Socket;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The {@link AbstractSocketEntry} extends the {@link AbstractServerSocket} and implements a generic
 * {@link Address} to {@link SocketChannel} mapping to be used by {@link org.snmp4j.TransportMapping}.
 * @param <A> the address type.
 * @author Frank Fock
 * @version 3.7.0
 */
public abstract class AbstractSocketEntry<A extends Address> extends AbstractServerSocket<A> {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractSocketEntry.class);

    protected SocketChannel socketChannel;
    private volatile int registrations = 0;
    private final LinkedList<byte[]> messages = new LinkedList<byte[]>();
    private final AtomicInteger busyLoops = new AtomicInteger(0);

    /**
     * Creates a socket entry with address and socket channel.
     * @param address
     *    the remote address associated with this socket entry.
     * @param socketChannel
     *    the socket channel holding the connection to the above remote address.
     */
    public AbstractSocketEntry(A address, SocketChannel socketChannel) {
        super(address);
        this.socketChannel = socketChannel;
    }

    /**
     * Adds a registration of a selection key to the specified {@link Selector}.
     * @param selector
     *    the {@link Selector} to be changed.
     * @param opKey
     *    the operation(s) to be registered.
     * @throws ClosedChannelException
     *    if the socket channel associated with the given selector is already closed.
     */
    public synchronized void addRegistration(Selector selector, int opKey)
            throws ClosedChannelException {
        if ((this.registrations & opKey) == 0) {
            this.registrations |= opKey;
            if (logger.isDebugEnabled()) {
                logger.debug("Adding operation " + getOperationListFromSelectionKey(opKey) + " for: " + this);
            }
            socketChannel.register(selector, registrations, this);
        } else if (!socketChannel.isRegistered()) {
            this.registrations = opKey;
            if (logger.isDebugEnabled()) {
                logger.debug("Registering new operation " + getOperationListFromSelectionKey(opKey) + " for: " + this);
            }
            socketChannel.register(selector, opKey, this);
        }
    }

    private static String getOperationListFromSelectionKey(int opKey) {
        StringBuilder buf = new StringBuilder();
        if ((opKey & SelectionKey.OP_READ) > 0) {
            buf.append("[READ]");
        }
        if ((opKey & SelectionKey.OP_WRITE) > 0) {
            buf.append("[WRITE]");
        }
        if ((opKey & SelectionKey.OP_ACCEPT) > 0) {
            buf.append("[ACCEPT]");
        }
        if ((opKey & SelectionKey.OP_CONNECT) > 0) {
            buf.append("[CONNECT]");
        }
        return buf.toString();
    }

    /**
     * Removes a registration of a selection key from the specified {@link Selector}.
     * @param selector
     *    the {@link Selector} to be changed.
     * @param opKey
     *    the operation(s) to be unregistered.
     * @throws ClosedChannelException
     *    if the socket channel associated with the given selector is already closed.
     */
    public synchronized void removeRegistration(Selector selector, int opKey) throws ClosedChannelException {
        if ((this.registrations & opKey) == opKey) {
            this.registrations &= ~opKey;
            socketChannel.register(selector, this.registrations, this);
            if (logger.isDebugEnabled()) {
                logger.debug("Removed operation(s) " + getOperationListFromSelectionKey(opKey) + " for: " + this);
            }
        }
    }

    /**
     * Check if the given operation(s) is registerd
     * @param opKey
     *    the operation(s) to check.
     * @return
     *    {@code true} if the given operation key(s) is/are registered, {@code false} otherwise.
     */
    public synchronized boolean isRegistered(int opKey) {
        return (this.registrations & opKey) == opKey;
    }

    /**
     * Gets the socket channel associated with this socket entry.
     * @return
     *    the socket channel.
     */
    public SocketChannel getSocketChannel() {
        return socketChannel;
    }

    /**
     * Gets the messages to be sent over this socket entry.
     * @return
     *    a list of byte arrays. Each byte array represents a message.
     */
    public List<byte[]> getMessages() {
        return messages;
    }

    /**
     * Add a message to be sent to the socket entries internal queue.
     * @param message
     *    a new message to be sent.
     */
    public synchronized void addMessage(byte[] message) {
        this.messages.add(message);
    }

    /**
     * Insert the given messages before already queued messages to the to-be-sent queue.
     * @param messages
     *    a new message to be sent.
     */
    public synchronized void insertMessages(List<byte[]> messages) {
        this.messages.addAll(0, messages);
    }

    /**
     * Gets the next message from the send queue.
     * @return
     *    the next message or {@code null} if there is no message to be sent left.
     */
    public synchronized byte[] nextMessage() {
        if (this.messages.size() > 0) {
            return this.messages.removeFirst();
        }
        return null;
    }

    /**
     * Check if there are messages to be sent.
     * @return
     *    {@code true} if there is at least one message to be sent queued.
     */
    public synchronized boolean hasMessage() {
        return !this.messages.isEmpty();
    }

    /**
     * Increase the busy looping counter and return it.
     * @return
     *    the current busy looping counter.
     */
    public synchronized int nextBusyLoop() {
        return busyLoops.incrementAndGet();
    }

    /**
     * Resets the busy looping counter to 0.
     */
    public void resetBusyLoops() {
        busyLoops.set(0);
    }

    public abstract String toString();

    /**
     * Close the (TLS) session associated with the socket entry.
     */
    public abstract void closeSession();

    /**
     * Gets the unique identifier of the associated (TLS) session.
     * @return
     *    a session identifier.
     */
    public abstract Object getSessionID();
}
