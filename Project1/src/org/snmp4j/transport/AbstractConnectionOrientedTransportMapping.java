/*_############################################################################
  _## 
  _##  SNMP4J - AbstractConnectionOrientedTransportMapping.java  
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
import org.snmp4j.util.WorkerTask;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The {@link AbstractConnectionOrientedTransportMapping} implements generic functions for a connection
 * oriented transport mapping for server and client connections.
 *
 * @param <A> the address type.
 * @param <S> the socket entry type.
 * @author Frank Fock
 * @since 3.7.0
 */
public abstract class AbstractConnectionOrientedTransportMapping<A extends Address, S extends AbstractSocketEntry<A>>
        extends AbstractTransportMapping<A> implements ConnectionOrientedTransportMapping<A> {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractConnectionOrientedTransportMapping.class);

    protected boolean serverEnabled = false;
    protected Map<A, S> sockets = new ConcurrentHashMap<>();
    private int maxBusyLoops = DefaultTcpTransportMapping.DEFAULT_MAX_BUSY_LOOPS;

    protected synchronized void timeoutSocket(AbstractSocketEntry<A> entry) {
        if ((connectionTimeout > 0) && (getSocketCleaner() != null)) {
            SocketTimeout<A> socketTimeout = new SocketTimeout<A>(this, entry);
            entry.setSocketTimeout(socketTimeout);
            getSocketCleaner().schedule(socketTimeout, connectionTimeout);
        }
    }

    /**
     * Gets the connection timeout. This timeout specifies the time a connection
     * may be idle before it is closed.
     *
     * @return long
     * the idle timeout in milliseconds.
     */
    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Sets the connection timeout. This timeout specifies the time a connection
     * may be idle before it is closed.
     *
     * @param connectionTimeout
     *         the idle timeout in milliseconds. A zero or negative value will disable
     *         any timeout and connections opened by this transport mapping will stay
     *         opened until they are explicitly closed.
     */
    public void setConnectionTimeout(long connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * Sets optional server socket options. The default implementation does
     * nothing.
     *
     * @param serverSocket
     *         the {@link ServerSocket} to apply additional non-default options.
     */
    protected void setSocketOptions(ServerSocket serverSocket) {
    }

    @Override
    public boolean isServerEnabled() {
        return serverEnabled;
    }

    @Override
    public void setServerEnabled(boolean serverEnabled) {
        this.serverEnabled = serverEnabled;
    }

    protected void closeSockets(Map<A, S> sockets) {
        List<A> closedSockets = new LinkedList<>();
        for (S entry : sockets.values()) {
            SocketChannel sc = entry.getSocketChannel();
            if (sc != null) {
                try {
                    try {
                        sc.socket().close();
                    } catch (UnsupportedOperationException unsupportedOperationException) {
                        // unix domain socket
                        sc.close();
                    }
                    if (logger.isDebugEnabled()) {
                        logger.debug("Socket channel to " + entry.getPeerAddress() + " closed");
                    }
                    TransportStateEvent e =
                            new TransportStateEvent(this, entry.getPeerAddress(),
                                    TransportStateEvent.STATE_CLOSED, null);
                    fireConnectionStateChanged(e);
                    closedSockets.add(entry.getPeerAddress());

                } catch (IOException iox) {
                    // ignore
                    logger.debug(iox);
                }
            }
        }
        for (A remoteAddress : closedSockets) {
            sockets.remove(remoteAddress);
        }
    }

    /**
     * Closes a connection to the supplied remote address, if it is open. This
     * method is particularly useful when not using a timeout for remote
     * connections.
     *
     * @param remoteAddress
     *         the address of the peer socket.
     *
     * @return {@code true} if the connection has been closed and
     * {@code false} if there was nothing to close.
     * @throws IOException
     *         if the remote address cannot be closed due to an IO exception.
     * @since 1.7.1
     */
    public synchronized boolean close(A remoteAddress) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Closing socket for peer address " + remoteAddress);
        }
        AbstractSocketEntry<A> entry = sockets.remove(remoteAddress);
        if (entry != null) {
            if (entry.getSocketTimeout() != null) {
                entry.getSocketTimeout().cancel();
            }
            SocketChannel sc = entry.getSocketChannel();
            if (sc != null) {
                try {
                    sc.socket().close();
                } catch (UnsupportedOperationException unsupportedOperationException) {
                    sc.close();
                    if (logger.isDebugEnabled()) {
                        logger.debug("Closed socket channel for peer address " + remoteAddress);
                    }
                }
                if (logger.isInfoEnabled()) {
                    logger.info("Socket to " + entry.getPeerAddress() + " closed");
                }
                TransportStateEvent e =
                        new TransportStateEvent(this, entry.getPeerAddress(),
                                TransportStateEvent.STATE_CLOSED, null);
                fireConnectionStateChanged(e);
            }
            return true;
        }
        return false;
    }

    /**
     * Closes all open sockets and stops the internal server thread that
     * processes messages.
     */
    public void close() throws IOException {
        for (S entry : sockets.values()) {
            entry.closeSession();
            TransportStateEvent e =
                    new TransportStateEvent(this, entry.getPeerAddress(), TransportStateEvent.STATE_CLOSED,
                            null);
            fireConnectionStateChanged(e);
        }
        WorkerTask st = listenWorkerTask;
        listenWorkerTask = null;
        if (st != null) {
            st.terminate();
            st.interrupt();
            try {
                st.join();
            } catch (InterruptedException ex) {
                logger.warn(ex);
            }
            closeSockets(sockets);
            if (getSocketCleaner() != null) {
                getSocketCleaner().cancel();
            }
            socketCleaner = null;
        }
    }

    public abstract void wakeupServerSelector();

    /**
     * Gets an unmodifiable map of the {@link AbstractSocketEntry} instances associated with this transport mapping.
     * @return
     *    an unmodifiable map from {@link Address} to {@link AbstractSocketEntry}.
     * @since 3.7.0
     */
    public Map<A, S> getSockets() {
        return Collections.unmodifiableMap(sockets);
    }

    protected void cancelNonServerSelectionKey(SelectionKey sk) {
        if (!sk.isAcceptable()) {
            sk.cancel();
        }
    }

    protected int getMaxBusyLoops() {
        return maxBusyLoops;
    }

    protected void setMaxBusyLoops(int maxBusyLoops) {
        this.maxBusyLoops = maxBusyLoops;
    }
}
