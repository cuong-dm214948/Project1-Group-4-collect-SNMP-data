/*_############################################################################
  _## 
  _##  SNMP4J - UdpAddress.java  
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
package org.snmp4j.smi;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * The <code>UdpAddress</code> represents UDP/IP transport addresses.
 *
 * @author Frank Fock
 * @version 3.0
 */
public class UdpAddress extends TransportIpAddress {

    static final long serialVersionUID = -4390734262648716203L;

    /**
     * Creates an empty UdpAddress without {@link #getInetAddress()} and zero port.
     */
    public UdpAddress() {
    }

    /**
     * Create a UdpAddress from the given {@link InetAddress} and port.
     * @param inetAddress
     *    the IP address portion of the UDP address to create.
     * @param port
     *    the UDP port.
     */
    public UdpAddress(InetAddress inetAddress, int port) {
        setInetAddress(inetAddress);
        setPort(port);
    }

    /**
     * Create a UdpAddress for the local host ({@link InetAddress#getLocalHost()}
     * with the provided port. If the local host is not known, a {@link RuntimeException}
     * is thrown.
     *
     * @param port
     *    the UDP port.
     */
    public UdpAddress(int port) {
        try {
            setInetAddress(InetAddress.getLocalHost());
        } catch (UnknownHostException e) {
           throw new RuntimeException(e);
        }
        setPort(port);
    }

    public UdpAddress(String address) {
        if (!parseAddress(address)) {
            throw new IllegalArgumentException(address);
        }
    }

    public static Address parse(String address) {
        UdpAddress a = new UdpAddress();
        if (a.parseAddress(address)) {
            return a;
        }
        return null;
    }

    public boolean equals(Object o) {
        return (o instanceof UdpAddress) && super.equals(o);
    }

}

