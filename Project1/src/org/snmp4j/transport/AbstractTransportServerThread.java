/*_############################################################################
  _## 
  _##  SNMP4J - AbstractTransportServerThread.java  
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
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.util.WorkerTask;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProtocolFamily;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * The {@link AbstractTransportServerThread} is a {@link WorkerTask} that serves server connections
 * using Java NIO for {@link ConnectionOrientedTransportMapping}s.
 *
 * @param <A> the address type supported.
 * @param <S> the socket entry supported.
 * @author Frank Fock
 * @since 3.7.0
 */
public abstract class AbstractTransportServerThread<A extends Address, S extends AbstractSocketEntry<A>> implements WorkerTask {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractTransportServerThread.class);

    protected final AbstractConnectionOrientedTransportMapping<A, S> transportMapping;
    protected final A serverAddress;
    protected volatile boolean stop = false;

    protected Selector selector;
    protected final LinkedList<S> pending = new LinkedList<>();
    protected Throwable lastError = null;
    protected ServerSocketChannel ssc;

    /**
     * Create a server thread for an {@link AbstractConnectionOrientedTransportMapping} on the specified
     * server address.
     * @param transportMapping
     *    the transport mapping using this thread to serve server messages.
     * @param serverAddress
     *    the listen address for the server.
     * @throws IOException
     *    if initializing NIO selector or listen address socket channel fails.
     */
    public AbstractTransportServerThread(AbstractConnectionOrientedTransportMapping<A, S> transportMapping, A serverAddress) throws IOException {
        this.transportMapping = transportMapping;
        this.serverAddress = serverAddress;
        selector = Selector.open();
    }

    protected void connectSocketToSendMessage(A address, byte[] message,
                                              SocketChannel socketChannel, S entry, Map<A, S> sockets) throws ClosedChannelException {
        S prevSocketEntry = sockets.putIfAbsent(address, entry);
        if (prevSocketEntry != null) {
            if (prevSocketEntry.getSocketChannel().isConnected()) {
                // reuse established connection
                entry = prevSocketEntry;
                if (logger.isDebugEnabled()) {
                    logger.debug("Concurrent connection attempt detected, canceling this one to " + address);
                }
                entry.addMessage(message);
                closeRedundantSocketChannelIfNeeded(address, socketChannel, prevSocketEntry, true);
            } else {
                // use last connection
                entry.insertMessages(prevSocketEntry.getMessages());
                sockets.put(address, entry);
                closeRedundantSocketChannelIfNeeded(address, socketChannel, prevSocketEntry, false);
            }
        }
        queueNewMessage(entry);
        logger.debug("Trying to connect to " + address);
    }

    private void closeRedundantSocketChannelIfNeeded(A address, SocketChannel socketChannel, S prevSocketEntry, boolean closeNew) {
        if (socketChannel != prevSocketEntry.getSocketChannel()) {
            // close new socket channel which is not needed any more
            try {
                if (closeNew) {
                    socketChannel.close();
                }
                else {
                    prevSocketEntry.getSocketChannel().close();
                }
            } catch (IOException iox) {
                logger.error("Failed to close redundantly opened socket for '" + address + "', with " +
                        iox.getMessage(), iox);
            }
        }
    }

    private void queueNewMessage(S entry) throws ClosedChannelException {
        synchronized (pending) {
            pending.add(entry);
        }
        selector.wakeup();
    }

    private void processPending() {
        synchronized (pending) {
            for (int i = 0; i < pending.size(); i++) {
                try {
                    S entry = pending.get(i);
                    try {
                        // Register the channel with the selector, indicating
                        // interest in connection completion and attaching the
                        // target object so that we can get the target back
                        // after the key is added to the selector's
                        // selected-key set
                        if (entry.getSocketChannel().isConnected()) {
                            if (entry.hasMessage() && entry.isHandshakeFinished()) {
                                entry.addRegistration(selector, SelectionKey.OP_WRITE);
                            }
                        } else if (entry.getSocketChannel().isOpen()) {
                            entry.addRegistration(selector, SelectionKey.OP_CONNECT);
                        }
                        else if (!entry.hasMessage()) {
                            pending.remove(entry);
                            i--;
                            if (logger.isDebugEnabled()) {
                                logger.debug("Removed closed socket entry without pending messages: " + entry);
                            }
                        }
                    } catch (CancelledKeyException ckex) {
                        logger.warn(ckex);
                        pending.remove(entry);
                        i--;
                        try {
                            entry.getSocketChannel().close();
                            TransportStateEvent e =
                                    new TransportStateEvent(transportMapping,
                                            entry.getPeerAddress(),
                                            TransportStateEvent.STATE_CLOSED,
                                            null);
                            transportMapping.fireConnectionStateChanged(e);
                        } catch (IOException ex) {
                            logger.error(ex);
                            ex.printStackTrace();
                        }
                    } catch (IOException iox) {
                        logger.error(iox);
                        iox.printStackTrace();
                        pending.remove(entry);
                        i--;
                        // Something went wrong, so close the channel and
                        // record the failure
                        try {
                            entry.getSocketChannel().close();
                            TransportStateEvent e =
                                    new TransportStateEvent(transportMapping,
                                            entry.getPeerAddress(),
                                            TransportStateEvent.STATE_CLOSED,
                                            iox);
                            transportMapping.fireConnectionStateChanged(e);
                        } catch (IOException ex) {
                            logger.error(ex);
                            ex.printStackTrace();
                        }
                        lastError = iox;
                        if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                            throw new RuntimeException(iox);
                        }
                    }
                } catch (NoSuchElementException noSuchElementException) {
                    // ignore
                }
            }
        }
    }

    protected abstract S createSocketEntry(A address, SocketChannel socketChannel,
                                           boolean useClientMode, TransportStateReference tmStateReference);

    /**
     * Send a message to the specified address and update to specified socket entry map if a new client connection
     * needs to be created for that.
     * @param address
     *    the remote address to send the message to.
     * @param message
     *    the message to be sent.
     * @param tmStateReference
     *    transport mapping state reference needed by transport mappings supporting message protocols
     *    {@link org.snmp4j.mp.MPv3} or higher.
     * @param sockets
     *    the client connections available and to be updated.
     * @throws IOException
     *    if sending the message failed because of IO exceptions.
     */
    public void sendMessage(A address, byte[] message, TransportStateReference tmStateReference, Map<A, S> sockets)
            throws IOException {
        SocketChannel sc = null;
        S entry = sockets.get(address);
        if (logger.isDebugEnabled()) {
            logger.debug("Looking up connection for destination '" + address + "' returned: " + entry);
            logger.debug(sockets.toString());
        }
        if (entry != null) {
            synchronized (entry) {
                entry.used();
                sc = entry.getSocketChannel();
            }
        }
        if ((sc == null) || (!sc.isOpen()) || (!sc.isConnected())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Socket for address '" + address + "' is closed, opening it...");
            }
            synchronized (pending) {
                pending.remove(entry);
            }
            try {
                SocketAddress targetAddress = address.getSocketAddress();
                if ((sc == null) || (!sc.isOpen())) {
                    // Open the channel, set it to non-blocking, initiate connect
                    sc = openSocketChannel(address.getFamily());
                    sc.configureBlocking(false);
                    sc.connect(targetAddress);
                } else {
                    sc.configureBlocking(false);
                    if (!sc.isConnectionPending()) {
                        sc.connect(targetAddress);
                    }
                }
                entry = createSocketEntry(address, sc, true, tmStateReference);
                if (entry != null) {
                    entry.addMessage(message);
                    connectSocketToSendMessage(address, message, sc, entry, sockets);
                }
                else {
                    logger.error("Socket channel not accepted and message not sent: "+sc+" from "+address);
                }
            } catch (IOException iox) {
                logger.error(iox);
                iox.printStackTrace();
                throw iox;
            }
        } else {
            entry.addMessage(message);
            logger.debug("Waking up selector for new message");
            queueNewMessage(entry);
        }
    }

    public Selector getSelector() {
        return selector;
    }

    protected abstract SocketChannel openSocketChannel(ProtocolFamily family) throws IOException;

    public abstract void run();

    protected abstract boolean readMessage(SelectionKey sk, SocketChannel readChannel,
                                            A incomingAddress, S socketEntry) throws IOException;

    /**
     * Do the NIO server processing.
     * @param sockets
     *    the sockets to serve.
     */
    protected void doServer(Map<A, S> sockets) {
        try {
            while (!stop) {
                try {
                    processQueues();
                    selector.select();
                    if (stop) {
                        break;
                    }
                    // Someone is ready for I/O, get the ready keys
                    Set<SelectionKey> readyKeys = selector.selectedKeys();
                    Iterator<SelectionKey> it = readyKeys.iterator();

                    // Walk through the ready keys collection and process data requests.
                    while (it.hasNext()) {
                        try {
                            S entry = null;
                            SelectionKey sk = it.next();
                            it.remove();
                            SocketChannel readChannel = null;
                            A incomingAddress = null;
                            if (sk.isAcceptable()) {
                                logger.debug("Key is acceptable");
                                // The key indexes into the selector, so you
                                // can retrieve the socket that's ready for I/O
                                ServerSocketChannel nextReady = (ServerSocketChannel) sk.channel();
                                readChannel = nextReady.accept();
                                readChannel.configureBlocking(false);

                                incomingAddress = createIncomingAddress(readChannel);
                                entry = createSocketEntry(incomingAddress, readChannel, false, null);
                                if (entry == null) {
                                    continue;
                                }
                                entry.addRegistration(selector, SelectionKey.OP_READ);
                                sockets.put(incomingAddress, entry);
                                transportMapping.timeoutSocket(entry);
                                TransportStateEvent e =
                                        new TransportStateEvent(transportMapping,
                                                incomingAddress,
                                                TransportStateEvent.STATE_CONNECTED,
                                                null);
                                transportMapping.fireConnectionStateChanged(e);
                                if (e.isCancelled()) {
                                    logger.warn("Incoming connection cancelled");
                                    readChannel.close();
                                    removeSocketEntry(incomingAddress);
                                    readChannel = null;
                                }
                            } else if (sk.isConnectable()) {
                                logger.debug("Key is connectable");
                                connectChannel(sk, incomingAddress);
                            } else {
                                if (sk.isWritable()) {
                                    logger.debug("Key is writable");
                                    incomingAddress = writeData(sk, incomingAddress);
                                }
                                if (sk.isReadable()) {
                                    logger.debug("Key is readable");
                                    readChannel = (SocketChannel) sk.channel();
                                    incomingAddress = createIncomingAddress(readChannel);
                                }
                            }
                            if (sk.isReadable() && readChannel != null) {
                                logger.debug("Key is reading");
                                try {
                                    if (!readMessage(sk, readChannel, incomingAddress, entry)) {
                                        if ((entry != null) && (transportMapping.getMaxBusyLoops() > 0)) {
                                            int busyLoops = entry.nextBusyLoop();
                                            if (busyLoops > transportMapping.getMaxBusyLoops()) {
                                                if (logger.isDebugEnabled()) {
                                                    logger.debug("After " + busyLoops + " read key has been removed: " + entry);
                                                }
                                                entry.removeRegistration(selector, SelectionKey.OP_READ);
                                                entry.resetBusyLoops();
                                            }
                                        }
                                    }
                                } catch (IOException iox) {
                                    // IO exception -> channel closed remotely
                                    logger.warn(iox);
                                    transportMapping.cancelNonServerSelectionKey(sk);
                                    readChannel.close();
                                    fireIncrementCounterSessionClose();
                                    removeSocketEntry(incomingAddress);
                                    TransportStateEvent e =
                                            new TransportStateEvent(transportMapping, incomingAddress,
                                                    TransportStateEvent.STATE_DISCONNECTED_REMOTELY,
                                                    iox);
                                    transportMapping.fireConnectionStateChanged(e);
                                }
                            }
                        } catch (CancelledKeyException ckex) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Selection key cancelled, skipping it");
                            }
                         }
                    }
                } catch (NullPointerException npex) {
                    // There seems to happen a NullPointerException within the select()
                    npex.printStackTrace();
                    logger.warn("NullPointerException within select()?");
                    stop = true;
                }
                if (!stop) {
                    processPending();
                }
            }
            if (ssc != null) {
                ssc.close();
                logger.debug("Closed server socket channel "+ssc);
            }
            if (selector != null) {
                selector.close();
            }
        } catch (IOException iox) {
            logger.error(iox);
            lastError = iox;
        }
        if (!stop) {
            stop = true;
            synchronized (transportMapping) {
                try {
                    transportMapping.close();
                } catch (IOException e) {
                    lastError = e;
                    logger.warn(e);
                }
            }
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Worker task finished: " + getClass().getName());
        }
    }

    protected void fireIncrementCounterSessionClose() {

    }

    protected abstract void processQueues();

    public abstract S removeSocketEntry(A incomingAddress);

    @SuppressWarnings("unchecked")
    protected void connectChannel(SelectionKey sk, A incomingAddress) {
        S entry = (S) sk.attachment();
        try {
            SocketChannel sc = (SocketChannel) sk.channel();
            if (!sc.isConnected()) {
                if (sc.finishConnect()) {
                    sc.configureBlocking(false);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Connected to " + entry.getPeerAddress());
                    }
                    // make sure connection is closed if not used for timeout
                    // micro seconds
                    transportMapping.timeoutSocket(entry);
                    entry.removeRegistration(selector, SelectionKey.OP_CONNECT);
                    entry.addRegistration(selector, SelectionKey.OP_WRITE);
                } else {
                    entry = null;
                }
            }
            if (entry != null) {
                Address addr = (incomingAddress == null) ? entry.getPeerAddress() : incomingAddress;
                logger.debug("Fire connected event for " + addr);
                TransportStateEvent e =
                        new TransportStateEvent(transportMapping, addr, TransportStateEvent.STATE_CONNECTED,
                                null);
                transportMapping.fireConnectionStateChanged(e);
            }
        } catch (IOException iox) {
            logger.warn(iox);
            sk.cancel();
            closeChannel(sk.channel());
            if (entry != null) {
                synchronized (pending) {
                    pending.remove(entry);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    protected A writeData(SelectionKey sk, A incomingAddress) {
        S entry = (S) sk.attachment();
        try {
            SocketChannel sc = (SocketChannel) sk.channel();
            incomingAddress = createIncomingAddress(sc);
            if ((entry != null) && (!entry.hasMessage())) {
                synchronized (pending) {
                    pending.remove(entry);
                    entry.removeRegistration(selector, SelectionKey.OP_WRITE);
                }
            }
            if (entry != null) {
                writeMessage(entry, sc);
            }
            else { // This should never happen, but if it happens we need to cancel the key to avoid a busy loop!
                sk.cancel();
                logger.warn("Key was writable for incoming address "+incomingAddress+" but SocketEntry is null, key is canceled");
            }
        } catch (IOException iox) {
            logger.warn(iox);
            // make sure channel is closed properly:
            closeChannel(sk.channel());
            removeSocketEntry(incomingAddress);
            TransportStateEvent e =
                    new TransportStateEvent(transportMapping, incomingAddress,
                            TransportStateEvent.STATE_DISCONNECTED_REMOTELY, iox);
            transportMapping.fireConnectionStateChanged(e);
        }
        return incomingAddress;
    }

    protected abstract A createIncomingAddress(SocketChannel socket) throws IOException;

    protected void closeChannel(SelectableChannel channel) {
        try {
            channel.close();
        } catch (IOException channelCloseException) {
            logger.warn(channelCloseException);
        }
    }

    protected void writeMessage(S entry, SocketChannel sc) throws
            IOException {
        byte[] message = entry.nextMessage();
        if (message != null) {
            entry.addRegistration(selector, SelectionKey.OP_READ);
            ByteBuffer buffer = ByteBuffer.wrap(message);
            sc.write(buffer);
            if (logger.isDebugEnabled()) {
                logger.debug("Sent message with length " +
                        message.length + " to " +
                        entry.getPeerAddress() + ": " +
                        new OctetString(message).toHexString());
            }
        } else {
            entry.removeRegistration(selector, SelectionKey.OP_WRITE);
            // Make sure that we did not clear a selection key that was concurrently
            // added:
            if (entry.hasMessage() && !entry.isRegistered(SelectionKey.OP_WRITE)) {
                entry.addRegistration(selector, SelectionKey.OP_WRITE);
                logger.debug("Waking up selector for write");
                selector.wakeup();
            }
        }
    }

    public void close() {
        stop = true;
        WorkerTask st = transportMapping.getListenWorkerTask();
        if (st != null) {
            st.terminate();
        }
    }

    @Override
    public void terminate() {
        stop = true;
        if (logger.isDebugEnabled()) {
            logger.debug("Terminated worker task: " + getClass().getName());
        }
    }

    @Override
    public void join() {
        if (logger.isDebugEnabled()) {
            logger.debug("Joining worker task: " + getClass().getName());
        }
    }

    @Override
    public void interrupt() {
        stop = true;
        if (logger.isDebugEnabled()) {
            logger.debug("Interrupting worker task: " + getClass().getName());
        }
        selector.wakeup();
    }
}
