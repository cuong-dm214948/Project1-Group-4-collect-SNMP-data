/*_############################################################################
  _## 
  _##  SNMP4J - ResponseEvent.java  
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
package org.snmp4j.event;

import java.util.EventObject;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.smi.Address;
// Imports needed for JavaDoc
import org.snmp4j.Session;

/**
 * {@code ResponseEvent} associates a request PDU with the corresponding
 * response and an optional user object.
 * @param <A> type of the peer {@link Address}.
 *
 * @author Frank Fock
 * @version 3.7.5
 */
public class ResponseEvent<A extends Address> extends EventObject {

    private static final long serialVersionUID = 3966730838956160070L;

    private A peerAddress;
    private PDU request;
    private PDU response;
    private Object userObject;
    private Exception error;
    /**
     * Nanoseconds between request send and response received.
     */
    private final long durationNanos;

    /**
     * Creates an {@code ResponseEvent} instance.
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
     * @deprecated Please use {@link ResponseEvent#ResponseEvent(Object, Address, PDU, PDU, Object, long)} instead.
     */
    public ResponseEvent(Object source, A peerAddress, PDU request, PDU response, Object userObject) {
        this(source, peerAddress, request, response, userObject, 0);
    }

    /**
     * Creates an {@code ResponseEvent} instance.
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
     * @param durationNanos
     *         duration of receiving the response for provided request in nanoseconds.
     */
    public ResponseEvent(Object source, A peerAddress, PDU request, PDU response, Object userObject,
                         long durationNanos) {
        super(source);
        setPeerAddress(peerAddress);
        setRequest(request);
        setResponse(response);
        setUserObject(userObject);
        this.durationNanos = durationNanos;
    }

    /**
     * Creates an {@code ResponseEvent} instance with an exception object indicating a message processing error.
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
     *         an {@code Exception}.
     * @param durationNanos
     *         duration of receiving the response for provided request in nanoseconds.
     */
    public ResponseEvent(Object source, A peerAddress, PDU request, PDU response, Object userObject, Exception error,
                         long durationNanos) {
        this(source, peerAddress, request, response, userObject, durationNanos);
        this.error = error;
    }

    /**
     * Gets the request PDU.
     *
     * @return a {@code PDU}.
     */
    public PDU getRequest() {
        return request;
    }

    protected final void setPeerAddress(A peerAddress) {
        this.peerAddress = peerAddress;
    }

    protected final void setRequest(PDU request) {
        this.request = request;
    }

    protected final void setResponse(PDU response) {
        this.response = response;
    }

    /**
     * Gets the response PDU.
     *
     * @return a PDU instance if a response has been received. If the request timed out then {@code null} will be
     * returned.
     */
    public PDU getResponse() {
        return response;
    }

    protected final void setUserObject(Object userObject) {
        this.userObject = userObject;
    }

    /**
     * Gets the user object that has been supplied to the asynchronous request {@link Session#send(PDU pdu,
     * org.snmp4j.Target target, Object userHandle, ResponseListener listener)}.
     *
     * @return an Object.
     */
    public Object getUserObject() {
        return userObject;
    }

    /**
     * Gets the exception object from the exception that has been generated when the request processing has failed due
     * to an error.
     *
     * @return an {@code Exception} instance.
     */
    public Exception getError() {
        return error;
    }

    /**
     * Gets the transport address of the response sender.
     *
     * @return the transport {@code Address} of the command responder that send this response, or {@code null}
     * if no response has been received within the time-out interval or if an error occured (see {@link #getError()}).
     */
    public A getPeerAddress() {
        return peerAddress;
    }

    /**
     * Gets the nanoseconds waited between request and response.
     * @return
     *    a value greater than 0 represents the nanoseconds {@link Snmp} waited until the response was received.
     * @since 3.7.5
     */
    public long getDurationNanos() {
        return durationNanos;
    }
}
