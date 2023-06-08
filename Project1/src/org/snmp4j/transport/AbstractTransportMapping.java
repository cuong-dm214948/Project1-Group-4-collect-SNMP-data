/*_############################################################################
  _## 
  _##  SNMP4J - AbstractTransportMapping.java  
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
import org.snmp4j.TransportMapping;
import org.snmp4j.MessageDispatcher;

import java.io.IOException;

import org.snmp4j.TransportStateReference;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.util.CommonTimer;
import org.snmp4j.util.DefaultThreadFactory;
import org.snmp4j.util.WorkerTask;

import java.nio.channels.SocketChannel;
import java.util.*;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The {@code AbstractTransportMapping} provides an abstract
 * implementation for the message dispatcher list and the maximum inbound
 * message size.
 *
 * @author Frank Fock
 * @version 3.6.0
 */
public abstract class AbstractTransportMapping<A extends Address> implements TransportMapping<A> {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractTransportMapping.class);

    protected List<TransportListener> transportListener = new ArrayList<TransportListener>(1);
    protected int maxInboundMessageSize = (1 << 16) - 1;
    protected boolean asyncMsgProcessingSupported = true;
    protected Set<A> suspendedAddresses = ConcurrentHashMap.newKeySet(5);
    protected WorkerTask listenWorkerTask;
    protected transient List<TransportStateListener> transportStateListeners;

    // 1 minute default timeout
    protected long connectionTimeout = 60000;
    protected CommonTimer socketCleaner;

    public abstract Class<? extends Address> getSupportedAddressClass();

    public boolean isListening() {
        return (listenWorkerTask != null);
    }

    /**
     * Sends a message to the supplied address using this transport. If the target address has been suspended,
     * then instead actually sending the message on the wire, the method
     * {@link #handleDroppedMessageToSend(Address, byte[], TransportStateReference, long, int)} will be called.
     * To stop suspending of a target address, call {@link #resumeAddress(Address)} for that address.
     *
     * @param address
     *         an {@code Address} instance denoting the target address.
     * @param message
     *         the whole message as an array of bytes.
     * @param tmStateReference
     *         the (optional) transport model state reference as defined by
     *         RFC 5590 section 6.1.
     * @param timeoutMillis
     *         maximum number of milliseconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     *
     * @throws IOException
     *         if any underlying IO operation fails.
     */
    public abstract void sendMessage(A address, byte[] message,
                                     TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws IOException;

    public synchronized void addTransportListener(TransportListener l) {
        if (!transportListener.contains(l)) {
            List<TransportListener> tlCopy = new ArrayList<>(transportListener);
            tlCopy.add(l);
            transportListener = tlCopy;
        }
    }

    public synchronized void removeTransportListener(TransportListener l) {
        if (transportListener != null && transportListener.contains(l)) {
            List<TransportListener> tlCopy = new ArrayList<>(transportListener);
            tlCopy.remove(l);
            transportListener = tlCopy;
        }
    }

    public synchronized void removeAllTransportListeners() {
        this.transportListener = new ArrayList<>(1);
    }

    protected void fireProcessMessage(A address, ByteBuffer buf,
                                      TransportStateReference tmStateReference) {
        if (transportListener != null) {
            for (TransportListener aTransportListener : transportListener) {
                aTransportListener.processMessage(this, address, buf, tmStateReference);
            }
        }
    }

    public abstract void close() throws IOException;

    /**
     * Suspend sending of messages to the specified address, regardless if a connection is already established or
     * not. To be able to send messages again to the specified address using
     * {@link #sendMessage(Address, byte[], TransportStateReference, long, int)}, call
     * {@link #resumeAddress(Address)}.
     * @param addressToSuspendSending
     *    an arbitrary remote address for which any messages send by
     *    {@link #sendMessage(Address, byte[], TransportStateReference, long, int)} should be dropped before sending
     *    and reopening a connection to that address.
     * @since 3.4.4
     */
    public void suspendAddress(A addressToSuspendSending) {
        if (suspendedAddresses.add(addressToSuspendSending)) {
            logger.info("Messages sending to "+addressToSuspendSending+" suspended");
        }
    }

    /**
     * Resume sending of messages to the specified address.
     * @param addressToResumeSending
     *    an arbitrary remote address for which any messages send by
     *    {@link #sendMessage(Address, byte[], TransportStateReference, long, int)} should be dropped before sending
     *    and reopening a connection to that address.
     * @return
     *    {@code true} if the specified address was previously suspended and is now resumed to allow sending messages,
     *    {@code false} otherwise.
     * @since 3.4.4
     */
    public boolean resumeAddress(A addressToResumeSending) {
        boolean resumed = suspendedAddresses.remove(addressToResumeSending);
        if (resumed) {
            logger.info("Messages sending to "+addressToResumeSending+" resumed");
        }
        return resumed;
    }

    /**
     * Handle a message that could not be send to the specified address, because there is no server socket for
     * receiving responses.
     * @param address
     *         an {@code Address} instance denoting the target address.
     * @param message
     *         the whole message as an array of bytes.
     * @param transportStateReference
     *         the (optional) transport model state reference as defined by
     *         RFC 5590 section 6.1.
     * @param timeoutMillis
     *         maximum number of milliseconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     * @since 3.4.4
     */
    protected void handleDroppedMessageToSend(A address, byte[] message,
                                              TransportStateReference transportStateReference,
                                              long timeoutMillis, int maxRetries) {
        logger.warn("Dropped message, because this transport mapping is suspended: address="+
                address+", message="+ OctetString.fromByteArray(message).toHexString());
    }

    public abstract void listen() throws IOException;

    /**
     * Gets the {@link CommonTimer} that controls socket cleanup operations.
     *
     * @return a socket cleaner timer.
     * @since 3.0
     */
    public CommonTimer getSocketCleaner() {
        return socketCleaner;
    }

    public int getMaxInboundMessageSize() {
        return maxInboundMessageSize;
    }

    /**
     * Returns {@code true} if asynchronous (multi-threaded) message
     * processing may be implemented. The default is {@code true}.
     *
     * @return if {@code false} is returned the
     * {@link MessageDispatcher#processMessage(org.snmp4j.TransportMapping, org.snmp4j.smi.Address, java.nio.ByteBuffer, org.snmp4j.TransportStateReference)}
     * method must not return before the message has been entirely processed.
     */
    public boolean isAsyncMsgProcessingSupported() {
        return asyncMsgProcessingSupported;
    }

    /**
     * Specifies whether this transport mapping has to support asynchronous
     * messages processing or not.
     *
     * @param asyncMsgProcessingSupported
     *         if {@code false} the {@link MessageDispatcher#processMessage(org.snmp4j.TransportMapping, org.snmp4j.smi.Address, java.nio.ByteBuffer, org.snmp4j.TransportStateReference)}
     *         method must not return before the message has been entirely processed,
     *         because the incoming message buffer is not copied before the message
     *         is being processed. If {@code true} the message buffer is copied
     *         for each call, so that the message processing can be implemented
     *         asynchronously.
     */
    public void setAsyncMsgProcessingSupported(
            boolean asyncMsgProcessingSupported) {
        this.asyncMsgProcessingSupported = asyncMsgProcessingSupported;
    }

    /**
     * Changes the priority of the listen thread for this UDP transport mapping.
     * This method has no effect, if called before {@link #listen()} has been
     * called for this transport mapping.
     * @param newPriority
     *         the new priority.
     * @see Thread#setPriority(int)
     * @since 3.6.0
     */
    public void setPriority(int newPriority) {
        WorkerTask lt = getListenWorkerTask();
        if (lt instanceof Thread) {
            ((Thread) lt).setPriority(newPriority);
        }
        else if (lt instanceof DefaultThreadFactory.WorkerThread) {
            ((DefaultThreadFactory.WorkerThread) lt).getThread().setPriority(newPriority);
        }
    }

    /**
     * Returns the priority of the internal listen thread.
     *
     * @return a value between {@link Thread#MIN_PRIORITY} and
     * {@link Thread#MAX_PRIORITY}.
     * @since 3.6.0
     */
    public int getPriority() {
        WorkerTask lt = getListenWorkerTask();
        if (lt instanceof Thread) {
            return ((Thread) lt).getPriority();
        }
        else if (lt instanceof DefaultThreadFactory.WorkerThread) {
            return ((DefaultThreadFactory.WorkerThread) lt).getThread().getPriority();
        } else {
            return Thread.NORM_PRIORITY;
        }
    }

    /**
     * Sets the name of the listen thread for this UDP transport mapping.
     * This method has no effect, if called before {@link #listen()} has been
     * called for this transport mapping.
     * @param name
     *         the new thread name.
     * @since 3.6.0
     */
    public void setThreadName(String name) {
        WorkerTask lt = getListenWorkerTask();
        if (lt instanceof Thread) {
            ((Thread) lt).setName(name);
        }
        else if (lt instanceof DefaultThreadFactory.WorkerThread) {
            ((DefaultThreadFactory.WorkerThread) lt).getThread().setName(name);
        }
    }

    /**
     * Returns the name of the listen thread.
     *
     * @return the thread name if in listening mode, otherwise {@code null}.
     * @since 3.6.0
     */
    public String getThreadName() {
        WorkerTask lt = getListenWorkerTask();
        if (lt instanceof Thread) {
            return ((Thread) lt).getName();
        }
        else if (lt instanceof DefaultThreadFactory.WorkerThread) {
            return ((DefaultThreadFactory.WorkerThread) lt).getThread().getName();
        } else {
            return null;
        }
    }

    /**
     * Add a {@link TransportStateListener} to get {@link TransportStateEvent}s if the state of this transport mapping
     * changes.
     * @param l
     *    the listener callback interface.
     * @since 3.7.0
     */
    public synchronized void addTransportStateListener(TransportStateListener l) {
        if (transportStateListeners == null) {
            transportStateListeners = new ArrayList<>(2);
        }
        transportStateListeners.add(l);
    }

    /**
     * Remove a {@link TransportStateListener} from this transport mapping.
     * @param l
     *    the listener callback interface to be removed.
     * @since 3.7.0
     */
    public synchronized void removeTransportStateListener(TransportStateListener l) {
        if (transportStateListeners != null) {
            transportStateListeners.remove(l);
        }
    }

    public abstract A getListenAddress();

    protected void fireConnectionStateChanged(TransportStateEvent change) {
        if (logger.isDebugEnabled()) {
            logger.debug("Firing transport state event: " + change);
        }
        final List<TransportStateListener> listenersFinalRef = transportStateListeners;
        if (listenersFinalRef != null) {
            try {
                List<TransportStateListener> listeners;
                synchronized (listenersFinalRef) {
                    listeners = new ArrayList<TransportStateListener>(listenersFinalRef);
                }
                for (TransportStateListener listener : listeners) {
                    listener.connectionStateChanged(change);
                }
            } catch (RuntimeException ex) {
                logger.error("Exception in fireConnectionStateChanged: " + ex.getMessage(), ex);
                if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                    throw ex;
                }
            }
        }
    }

    /**
     * Gets the {@link WorkerTask} that is responsible for receiving new messages.
     * @return
     *    a {@link WorkerTask} instance which is most likely a {@link org.snmp4j.util.DefaultThreadFactory.WorkerThread}.
     * @since 3.7.0
     */
    public WorkerTask getListenWorkerTask() {
        return listenWorkerTask;
    }

    /**
     * Gets a unmodifiable set of the suspended addresses of this
     * @return
     */
    public Set<A> getSuspendedAddresses() {
        return Collections.unmodifiableSet(suspendedAddresses);
    }
}
