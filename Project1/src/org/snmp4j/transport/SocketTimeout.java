/*_############################################################################
  _## 
  _##  SNMP4J - SocketTimeout.java  
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
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;

import java.io.IOException;
import java.util.TimerTask;

/**
 * The {@link SocketTimeout} is a {@link TimerTask} that provides means to detect when a socket is not used for
 * predefined time and then close the socket and free its resources.
 * @author Frank Fock
 * @since 3.0
 */
public class SocketTimeout<A extends Address> extends TimerTask {
    private static final LogAdapter logger = LogFactory.getLogger(SocketTimeout.class);

    private final ConnectionOrientedTransportMapping<A> transportMapping;
    private AbstractServerSocket<A> entry;

    /**
     * Create a socket timeout handler for the provided {@link org.snmp4j.TransportMapping} and server socket entry.
     * @param transportMapping
     *   a {@link ConnectionOrientedTransportMapping} that acts as a server.
     * @param entry
     *   a {@link AbstractSocketEntry} representing a server socket for a client connection associated with the above
     *   transport mapping.
     */
    public SocketTimeout(ConnectionOrientedTransportMapping<A> transportMapping, AbstractServerSocket<A> entry) {
        this.transportMapping = transportMapping;
        this.entry = entry;
    }

    /**
     * Runs a timeout check and if the socket has timed out, it removes the socket from the associated
     * {@link org.snmp4j.TransportMapping}.
     */
    public void run() {
        long now = System.nanoTime();
        if ((transportMapping.getSocketCleaner() == null) ||
                ((now - entry.getLastUse()) / SnmpConstants.MILLISECOND_TO_NANOSECOND >=
                        transportMapping.getConnectionTimeout())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Socket has not been used for " +
                        (now - entry.getLastUse()) +
                        " milliseconds, closing it");
            }
            AbstractServerSocket<A> entryCopy = entry;
            try {
                transportMapping.close(entryCopy.getPeerAddress());
                logger.info("Socket to " + entryCopy.getPeerAddress() + " closed due to timeout");
            } catch (IOException e) {
                logger.error("Failed to close transport mapping for peer address " +
                        entry.getPeerAddress() + ": " + e.getMessage(), e);
            }
        } else {
            long nextRun = System.currentTimeMillis() +
                    (now - entry.getLastUse()) / SnmpConstants.MILLISECOND_TO_NANOSECOND +
                    transportMapping.getConnectionTimeout();
            if (logger.isDebugEnabled()) {
                logger.debug("Scheduling " + nextRun);
            }
            SocketTimeout<A> socketTimeout = new SocketTimeout<A>(transportMapping, entry);
            entry.setSocketTimeout(socketTimeout);
            transportMapping.getSocketCleaner().schedule(socketTimeout, nextRun);
        }
    }

    public boolean cancel() {
        boolean result = super.cancel();
        // free objects early
        entry = null;
        return result;
    }
}
