/*_############################################################################
  _##
  _##  SNMP4J - ResponseEvent.java
  _##
  _##  Copyright (C) 2003-2023  Frank Fock (SNMP4J.org)
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

package org.snmp4j.event;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.smi.Address;

/**
 * The {@code ResponseFactory} can be implemented to create {@link ResponseEvent}s on behalf of an {@link Snmp}
 * instance. Although there is a default implementation, a custom one could add some special logging or response
 * time monitoring.
 * @param <A>
 * @since 3.7.5
 */
public interface ResponseEventFactory {

    /**
     * Creates an {@code ResponseEvent} instance with an exception object indicating a message processing error.
     * The default implementation calls {@link ResponseEvent#ResponseEvent(Object, Address, PDU, PDU, Object, Exception)}
     * to create a {@link ResponseEvent} new instance with the provided parameters.
     *
     * @param source
     *         the event source.
     * @param peerAddress
     *         the transport address of the entity that send the response.
     * @param request
     *         the request PDU (must not be {@code null}).
     * @param response
     *         the response PDU or {@code null} if the request timed out.
     * @param userObject
     *         an optional user object.
     * @param error
     *         an {@code Exception} or {@code null} if no error occurred.
     */
    default <A extends Address> ResponseEvent<A> createResponseEvent(Object source, A peerAddress,
                                                                    PDU request, PDU response,
                                                                    Object userObject,
                                                                    long durationNanos,
                                                                    Exception error) {
        return new ResponseEvent<A>(source, peerAddress, request, response, userObject, error, durationNanos);
    }

}
