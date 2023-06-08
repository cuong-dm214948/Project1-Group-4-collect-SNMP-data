/*_############################################################################
  _## 
  _##  SNMP4J - DefaultUdpTransportMapping.java  
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
import java.net.*;
import java.nio.ByteBuffer;

import org.snmp4j.TransportStateReference;
import org.snmp4j.log.*;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.*;
import org.snmp4j.SNMP4JSettings;

import java.io.InterruptedIOException;
import java.util.Collections;
import java.util.List;

import org.snmp4j.util.WorkerTask;

/**
 * The {@code DefaultUdpTransportMapping} implements a UDP transport
 * mapping based on Java standard IO and using an internal thread for
 * listening on the inbound socket.
 *
 * @author Frank Fock
 * @version 1.9
 */
public class DefaultUdpTransportMapping extends UdpTransportMapping {

    private static final LogAdapter logger =
            LogFactory.getLogger(DefaultUdpTransportMapping.class);

    protected DatagramSocket socket = null;
    protected ListenThread listenerThread;
    private int socketTimeout = 0;

    private int receiveBufferSize = 0; // not set by default

    /**
     * Creates a UDP transport with an arbitrary local port on all local
     * interfaces.
     *
     * @throws SocketException
     *         if socket binding fails.
     */
    public DefaultUdpTransportMapping() throws SocketException {
        super(new UdpAddress("0.0.0.0/0"));
        socket = new DatagramSocket(udpAddress.getPort());
    }

    /**
     * Creates a UDP transport with optional reusing the address if is currently
     * in timeout state (TIME_WAIT) after the connection is closed.
     *
     * @param udpAddress
     *         the local address for sending and receiving of UDP messages.
     * @param reuseAddress
     *         if {@code true} addresses are reused which provides faster socket
     *         binding if an application is restarted for instance.
     *
     * @throws SocketException
     *         if socket binding fails.
     * @since 1.7.3
     */
    public DefaultUdpTransportMapping(UdpAddress udpAddress,
                                      boolean reuseAddress) throws SocketException {
        super(udpAddress);
        socket = new DatagramSocket(null);
        socket.setReuseAddress(reuseAddress);
        final SocketAddress addr =
                new InetSocketAddress(udpAddress.getInetAddress(), udpAddress.getPort());
        socket.bind(addr);
    }

    /**
     * Creates a UDP transport on the specified address. The address will not be
     * reused if it is currently in timeout state (TIME_WAIT).
     *
     * @param udpAddress
     *         the local address for sending and receiving of UDP messages.
     *
     * @throws IOException
     *         if socket binding fails.
     */
    public DefaultUdpTransportMapping(UdpAddress udpAddress) throws IOException {
        super(udpAddress);
        socket = new DatagramSocket(udpAddress.getPort(), udpAddress.getInetAddress());
    }

    @Override
    public void sendMessage(UdpAddress targetAddress, byte[] message,
                            TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws java.io.IOException {
        if ((suspendedAddresses.size() > 0) && suspendedAddresses.contains(targetAddress)) {
            handleDroppedMessageToSend(targetAddress, message, tmStateReference, timeoutMillis, maxRetries);
            return;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Sending message to " + targetAddress + " from " + getListenAddress() + " with length " +
                    message.length + ": " +
                    new OctetString(message).toHexString());
        }
        DatagramSocket s = ensureSocket();
        List<DatagramPacket> netPayload =
                prepareOutPackets(targetAddress, message, tmStateReference, s, timeoutMillis, maxRetries);
        for (DatagramPacket netPacket : netPayload) {
            if (logger.isDebugEnabled()) {
                logger.debug("Sending packet to "+targetAddress);
            }
            s.send(netPacket);
        }
    }

    /**
     * Prepare an application message for sending over the network to the specified target address.
     *
     * @param targetAddress
     *         the UDP address the message will be sent to.
     * @param message
     *         the application message to send.
     * @param tmStateReference
     *         the transport state reference associated with this message.
     * @param socket
     *         the socket that will send the message over the network.  @return
     *         an ByteBuffer that contains the network representation of the message (i.e. encrypted).
     * @param timeoutMillis
     *         maximum number of milli seconds the connection creation might take (if connection based).
     *         Use 0 for responses or transport mappings that do not require connection establishment.
     * @param maxRetries
     *         maximum retries during connection creation. Use 0 for responses.
     *
     * @return a list of prepared {@link DatagramPacket} instances. By default this is a singleton list.
     * @throws IOException
     *         if the preparation of the network message fails (e.g. because the encryption handshake fails).
     */
    protected List<DatagramPacket> prepareOutPackets(UdpAddress targetAddress, byte[] message,
                                                     TransportStateReference tmStateReference, DatagramSocket socket,
                                                     long timeoutMillis, int maxRetries)
            throws IOException {
        InetSocketAddress targetSocketAddress =
                new InetSocketAddress(targetAddress.getInetAddress(),
                        targetAddress.getPort());
        return Collections.singletonList(new DatagramPacket(message, message.length, targetSocketAddress));
    }

    /**
     * Closes the socket and stops the listener thread.
     *
     * @throws IOException
     *         if the socket cannot be closed.
     */
    public void close() throws IOException {
        boolean interrupted = false;
        WorkerTask l = getListenWorkerTask();
        if (l != null) {
            l.terminate();
            l.interrupt();
            if (socketTimeout > 0) {
                try {
                    l.join();
                } catch (InterruptedException ex) {
                    interrupted = true;
                    logger.warn(ex);
                }
            }
            listenWorkerTask = null;
        }
        DatagramSocket closingSocket = socket;
        if ((closingSocket != null) && (!closingSocket.isClosed())) {
            closingSocket.close();
        }
        socket = null;
        TransportStateEvent e =
                new TransportStateEvent(this, getListenAddress(),
                        TransportStateEvent.STATE_CLOSED, null);
        fireConnectionStateChanged(e);
        if ((l != null) && (socketTimeout <= 0)) {
            try {
                l.join();
            } catch (InterruptedException ex) {
                interrupted = true;
                logger.warn(ex);
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Starts the listener thread that accepts incoming messages. The thread is
     * started in daemon mode, and thus it will not block application termination.
     * Nevertheless, the {@link #close()} method should be called to stop the
     * listen thread gracefully and free associated resources.
     *
     * @throws IOException
     *         if the listen port could not be bound to the server thread.
     */
    public synchronized void listen() throws IOException {
        if (getListenWorkerTask() != null) {
            throw new SocketException("Port already listening");
        }
        ensureSocket();
        listenerThread = new ListenThread();
        listenWorkerTask = SNMP4JSettings.getThreadFactory().createWorkerThread(
                "DefaultUDPTransportMapping_" + getListenAddress(), listenerThread, true);
        getListenWorkerTask().run();
        TransportStateEvent e =
                new TransportStateEvent(this, getListenAddress(),
                        TransportStateEvent.STATE_CONNECTED, null);
        fireConnectionStateChanged(e);
    }

    protected synchronized DatagramSocket ensureSocket() throws SocketException {
        DatagramSocket s = socket;
        if (s == null) {
            s = new DatagramSocket(udpAddress.getPort());
            s.setSoTimeout(socketTimeout);
            this.socket = s;
        }
        return s;
    }

    public void setMaxInboundMessageSize(int maxInboundMessageSize) {
        this.maxInboundMessageSize = maxInboundMessageSize;
    }

    /**
     * Returns the socket timeout.
     * 0 returns implies that the option is disabled (i.e., timeout of infinity).
     *
     * @return the socket timeout setting.
     */
    public int getSocketTimeout() {
        return socketTimeout;
    }

    /**
     * Gets the requested receive buffer size for the underlying UDP socket.
     * This size might not reflect the actual size of the receive buffer, which
     * is implementation specific.
     *
     * @return &lt;=0 if the default buffer size of the OS is used, or a value &gt;0 if the
     * user specified a buffer size.
     */
    public int getReceiveBufferSize() {
        return receiveBufferSize;
    }

    /**
     * Sets the receive buffer size, which should be greater than the maximum inbound message
     * size. This method has to be called before {@link #listen()} to be
     * effective.
     *
     * @param receiveBufferSize
     *         an integer value &gt;0 and &gt; {@link #getMaxInboundMessageSize()}.
     */
    public void setReceiveBufferSize(int receiveBufferSize) {
        if (receiveBufferSize <= 0) {
            throw new IllegalArgumentException("Receive buffer size must be > 0");
        }
        this.receiveBufferSize = receiveBufferSize;
    }

    /**
     * Sets the socket timeout in milliseconds.
     *
     * @param socketTimeout
     *         the socket timeout for incoming messages in milliseconds.
     *         A timeout of zero is interpreted as an infinite timeout.
     */
    public void setSocketTimeout(int socketTimeout) {
        this.socketTimeout = socketTimeout;
        if (socket != null) {
            try {
                socket.setSoTimeout(socketTimeout);
            } catch (SocketException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    @Override
    public UdpAddress getListenAddress() {
        UdpAddress actualListenAddress = null;
        DatagramSocket socketCopy = socket;
        if (socketCopy != null) {
            actualListenAddress = new UdpAddress(socketCopy.getLocalAddress(), socketCopy.getLocalPort());
        }
        return actualListenAddress;
    }

    /**
     * If receiving new datagrams fails with a {@link SocketException}, this method is called to renew the
     * socket - if possible.
     *
     * @param socketException
     *         the exception that occurred.
     * @param failedSocket
     *         the socket that caused the exception. By default, he socket will be closed
     *         in order to be able to reopen it. Implementations may also try to reuse the socket, in dependence
     *         of the {@code socketException}.
     *
     * @return the new socket or {@code null} if the listen thread should be terminated with the provided
     * exception.
     * @throws SocketException
     *         a new socket exception if the socket could not be renewed.
     * @since 2.2.2
     */
    protected DatagramSocket renewSocketAfterException(SocketException socketException,
                                                       DatagramSocket failedSocket) throws SocketException {
        if ((failedSocket != null) && (!failedSocket.isClosed())) {
            failedSocket.close();
        }
        DatagramSocket s = new DatagramSocket(udpAddress.getPort(), udpAddress.getInetAddress());
        s.setSoTimeout(socketTimeout);
        return s;
    }

    protected class ListenThread implements WorkerTask {

        private byte[] buf;
        private volatile boolean stop = false;


        public ListenThread() throws SocketException {
            buf = new byte[getMaxInboundMessageSize()];
        }

        public void run() {
            DatagramSocket socketCopy = socket;
            if (socketCopy != null) {
                try {
                    socketCopy.setSoTimeout(getSocketTimeout());
                    if (receiveBufferSize > 0) {
                        socketCopy.setReceiveBufferSize(Math.max(receiveBufferSize,
                                maxInboundMessageSize));
                    }
                    if (logger.isDebugEnabled()) {
                        logger.debug("UDP receive buffer size for socket " +
                                getAddress() + " is set to: " +
                                socketCopy.getReceiveBufferSize());
                    }
                } catch (SocketException ex) {
                    logger.error(ex);
                    setSocketTimeout(0);
                }
                if (logger.isInfoEnabled()) {
                    logger.info("Listening on socket " + new UdpAddress(socketCopy.getLocalAddress(), socketCopy.getLocalPort()));
                }
            }
            while (!stop) {
                if (isAsyncMsgProcessingSupported() || (buf == null)) {
                    buf = new byte[getMaxInboundMessageSize()];
                }
                DatagramPacket packet = new DatagramPacket(buf, buf.length,
                        udpAddress.getInetAddress(),
                        udpAddress.getPort());
                try {
                    socketCopy = socket;
                    ByteBuffer bis;
                    TransportStateReference stateReference =
                            new TransportStateReference(DefaultUdpTransportMapping.this, udpAddress, null,
                                    SecurityLevel.undefined, SecurityLevel.undefined,
                                    false, socketCopy);
                    try {
                        if (socketCopy == null) {
                            stop = true;
                            continue;
                        }
                        try {
                            socketCopy.receive(packet);
                        } catch (SocketTimeoutException ste) {
                            continue;
                        }
                        bis = prepareInPacket(packet, buf, stateReference);
                    } catch (InterruptedIOException iiox) {
                        if (iiox.bytesTransferred <= 0) {
                            continue;
                        }
                        bis = prepareInPacket(packet, buf, stateReference);
                    }
                    if (logger.isDebugEnabled()) {
                        logger.debug("Received message from " + packet.getAddress() + "/" +
                                packet.getPort() +
                                " with length " + packet.getLength() + ": " +
                                new OctetString(packet.getData(), 0,
                                        packet.getLength()).toHexString());
                    }
                    if (bis != null) {
                        fireProcessMessage(packet, bis, stateReference);
                    }
                } catch (SocketTimeoutException stex) {
                    // ignore
                } catch (PortUnreachableException purex) {
                    synchronized (DefaultUdpTransportMapping.this) {
                        listenWorkerTask = null;
                    }
                    logger.error(purex);
                    if (logger.isDebugEnabled()) {
                        purex.printStackTrace();
                    }
                    if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                        throw new RuntimeException(purex);
                    }
                    break;
                } catch (SocketException soex) {
                    if (!stop) {
                        logger.warn("Socket for transport mapping " + toString() + " error: " + soex.getMessage());
                    }
                    if (!stop && SNMP4JSettings.isForwardRuntimeExceptions()) {
                        stop = true;
                        throw new RuntimeException(soex);
                    } else if (!stop) {
                        try {
                            DatagramSocket newSocket = renewSocketAfterException(soex, socketCopy);
                            if (newSocket == null) {
                                throw soex;
                            }
                            socket = newSocket;
                        } catch (SocketException e) {
                            stop = true;
                            socket = null;
                            logger.error("Socket renewal for transport mapping " + toString() +
                                    " failed with: " + e.getMessage(), e);

                        }
                    }
                } catch (IOException iox) {
                    logger.warn(iox);
                    if (logger.isDebugEnabled()) {
                        iox.printStackTrace();
                    }
                    if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                        throw new RuntimeException(iox);
                    }
                }
            }
            synchronized (DefaultUdpTransportMapping.this) {
                listenWorkerTask = null;
                stop = true;
                DatagramSocket closingSocket = socket;
                if ((closingSocket != null) && (!closingSocket.isClosed())) {
                    closingSocket.close();
                }
                socket = null;
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Worker task stopped:" + getClass().getName());
            }
        }

        public void close() {
            stop = true;
        }

        public void terminate() {
            close();
            if (logger.isDebugEnabled()) {
                logger.debug("Terminated worker task: " + getClass().getName());
            }
        }

        public void join() throws InterruptedException {
            if (logger.isDebugEnabled()) {
                logger.debug("Joining worker task: " + getClass().getName());
            }
        }

        public void interrupt() {
            if (logger.isDebugEnabled()) {
                logger.debug("Interrupting worker task: " + getClass().getName());
            }
            close();
        }
    }

    protected void fireProcessMessage(DatagramPacket packet, ByteBuffer bis, TransportStateReference stateReference) {
        fireProcessMessage(new UdpAddress(packet.getAddress(), packet.getPort()), bis, stateReference);
    }

    /**
     * Prepare a network packet for the application.
     *
     * @param packet
     *         the incoming network datagram packet.
     * @param buf
     *         the buffer of the packet.
     * @param tmStateReference
     *         the transport state reference.
     *
     * @return a byte buffer with the application data of the packet.
     * @throws IOException
     *         if there occurs an IO exception during preparation.
     * @since 3.0
     */
    protected ByteBuffer prepareInPacket(DatagramPacket packet, byte[] buf, TransportStateReference tmStateReference)
            throws IOException {
        return ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
    }
}
