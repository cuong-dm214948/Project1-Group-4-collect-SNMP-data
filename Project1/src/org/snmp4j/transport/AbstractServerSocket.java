/*_############################################################################
  _## 
  _##  SNMP4J - AbstractServerSocket.java  
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

import org.snmp4j.smi.Address;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.util.CommonTimer;

import java.net.Socket;
import java.util.Map;

/**
 * The {@code AbstractServerSocket} interface provides methods to manage the sockets of a connection oriented
 * transport mapping listening for incoming requests.
 *
 * @author Frank Fock
 * @version 3.0
 * @since 3.0
 */
public abstract class AbstractServerSocket<A extends Address> {

    private long lastUse;
    private final A peerAddress;
    private boolean handshakeFinished;
    private SocketTimeout<A> socketTimeout;

    public AbstractServerSocket(A address) {
        this.peerAddress = address;
        this.lastUse = System.nanoTime();
    }

    public long getLastUse() {
        return lastUse;
    }

    public void used() {
        lastUse = System.nanoTime();
    }

    public A getPeerAddress() {
        return peerAddress;
    }

    public SocketTimeout<A> getSocketTimeout() {
        return socketTimeout;
    }

    public void setSocketTimeout(SocketTimeout<A> socketTimeout) {
        this.socketTimeout = socketTimeout;
    }

    public boolean isHandshakeFinished() {
        return handshakeFinished;
    }

    public void setHandshakeFinished(boolean handshakeFinished) {
        this.handshakeFinished = handshakeFinished;
    }
}
