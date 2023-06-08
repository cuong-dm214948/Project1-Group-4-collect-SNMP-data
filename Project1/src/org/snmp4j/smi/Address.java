/*_############################################################################
  _## 
  _##  SNMP4J - Address.java  
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

import java.net.ProtocolFamily;
import java.net.SocketAddress;

/**
 * The {@code Address} interface serves as a base class for all SNMP transport addresses.
 *
 * @author Frank Fock
 * @version 3.2.0
 */
public interface Address extends AssignableFromString, AssignableFromByteArray {

    /**
     * Checks whether this {@code Address} is a valid transport address.
     *
     * @return {@code true} if the address is valid, {@code false} otherwise.
     */
    boolean isValid();

    /**
     * Parses the address from the supplied string representation.
     *
     * @param address
     *         a String representation of this address.
     *
     * @return {@code true} if {@code address} could be successfully parsed and has been assigned to this address
     * object, {@code false} otherwise.
     */
    boolean parseAddress(String address);

    /**
     * Sets the address value from the supplied String. The string must match the format required for the Address
     * instance implementing this interface. Otherwise an {@link IllegalArgumentException} runtime exception is thrown.
     *
     * @param address
     *         an address String.
     *
     * @since 1.7
     */
    void setValue(String address);

    /**
     * Checks if the supplied address class is compatible with this class. For example, secure transport classes like
     * TLS are not compatible with TCP because the latter is not able to provide the required security characteristics.
     *
     * @param other
     *         the {@link Address} class to check for compatibility.
     *
     * @return {@code true} if the provided address class has the same (compatible) on-the-wire characteristics than
     * this address class. By default, this is {@code true} if the provided class {@code other} is the same or a
     * subclass than this class.
     * @since 3.2.0
     */
    default boolean isTransportCompatible(Class<?> other) {
        return other.isAssignableFrom(this.getClass());
    }

    /**
     * Gets the protocol family of this address.
     * @return
     *    a protocol family.
     * @since 3.7.0
     */
    ProtocolFamily getFamily();

    /**
     * Gets the socket address of this address.
     * @return
     *    the socket address representation (if available) of this address or {@code null} if that does not exist
     *    (yet).
     * @since 3.7.0
     */
    SocketAddress getSocketAddress();
}

