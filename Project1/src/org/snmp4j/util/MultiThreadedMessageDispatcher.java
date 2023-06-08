/*_############################################################################
  _## 
  _##  SNMP4J - MultiThreadedMessageDispatcher.java  
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
package org.snmp4j.util;

import org.snmp4j.*;
import org.snmp4j.event.CounterListener;
import org.snmp4j.mp.MessageProcessingModel;

import java.util.Collection;

import org.snmp4j.smi.Address;
import org.snmp4j.mp.PduHandle;
import org.snmp4j.mp.StateReference;
import org.snmp4j.mp.StatusInformation;

import java.nio.ByteBuffer;

import org.snmp4j.mp.PduHandleCallback;
import org.snmp4j.transport.TransportType;

/**
 * The {@code MultiThreadedMessageDispatcher} class is a decorator
 * for any {@code MessageDispatcher} instances that processes incoming
 * message with a supplied {@code ThreadPool}. The processing is thus
 * concurrent on up to the size of the supplied thread pool threads.
 * <p>
 * In contrast to a {@link MessageDispatcherImpl} a
 * {@code MultiThreadedMessageDispatcher} copies the incoming
 * {@code ByteBuffer} for {@link #processMessage(TransportMapping, Address, ByteBuffer, TransportStateReference)}
 * to allow concurrent processing of the buffer.
 *
 * @author Frank Fock
 * @version 3.5.0
 * @since 1.0.2
 */
public class MultiThreadedMessageDispatcher implements MessageDispatcher {

    private final MessageDispatcher dispatcher;
    private final WorkerPool threadPool;

    /**
     * Creates a multithreaded message dispatcher using the provided
     * {@code ThreadPool} to concurrently process incoming messages
     * that are forwarded to the supplied decorated
     * {@code MessageDispatcher}.
     *
     * @param workerPool
     *         a {@code WorkerPool} instance (that can be shared). <em>The worker
     *         pool has to be stopped externally.</em>
     * @param decoratedDispatcher
     *         the decorated {@code MessageDispatcher} that must be
     *         multi-threading safe.
     */
    public MultiThreadedMessageDispatcher(WorkerPool workerPool, MessageDispatcher decoratedDispatcher) {
        this.threadPool = workerPool;
        this.dispatcher = decoratedDispatcher;
    }

    /**
     * Returns the wrapped dispatcher.
     * @return
     *    the {@link MessageDispatcher} instance called by the threads of the worker pool.
     * @since 3.5.0
     */
    public MessageDispatcher getDispatcher() {
        return dispatcher;
    }

    public int getNextRequestID() {
        return dispatcher.getNextRequestID();
    }

    public void addMessageProcessingModel(MessageProcessingModel model) {
        dispatcher.addMessageProcessingModel(model);
    }

    public void removeMessageProcessingModel(MessageProcessingModel model) {
        dispatcher.removeMessageProcessingModel(model);
    }

    public MessageProcessingModel getMessageProcessingModel(int messageProcessingModel) {
        return dispatcher.getMessageProcessingModel(messageProcessingModel);
    }

    public void addTransportMapping(TransportMapping<? extends Address> transport) {
        dispatcher.addTransportMapping(transport);
    }

    public TransportMapping<?> removeTransportMapping(TransportMapping<? extends Address> transport) {
        return dispatcher.removeTransportMapping(transport);
    }

    /**
     * Adds a {@link CounterListener} to the dispatcher. The counter listener
     * is informed about errors during message dispatching.
     *
     * @param counterListener
     *         a {@code CounterListener} instance.
     *
     * @since 3.0
     */
    @Override
    public void addCounterListener(CounterListener counterListener) {
        dispatcher.addCounterListener(counterListener);
    }

    /**
     * Removes a previously added {@link CounterListener} from the dispatcher.
     *
     * @param counterListener
     *         a {@code CounterListener} instance.
     *
     * @return the {@code CounterListener} instance if it
     * could be successfully removed, {@code null} otherwise.
     * @since 3.0
     */
    @Override
    public CounterListener removeCounterListener(CounterListener counterListener) {
        return dispatcher.removeCounterListener(counterListener);
    }

    public Collection<TransportMapping<? extends Address>> getTransportMappings() {
        return dispatcher.getTransportMappings();
    }

    public void addCommandResponder(CommandResponder listener) {
        dispatcher.addCommandResponder(listener);
    }

    public void removeCommandResponder(CommandResponder listener) {
        dispatcher.removeCommandResponder(listener);
    }

    public <A extends Address> PduHandle sendPdu(Target<A> target, PDU pdu, boolean expectResponse)
            throws MessageException {
        return dispatcher.sendPdu(target, pdu, expectResponse);
    }

    public <A extends Address> PduHandle sendPdu(TransportMapping<? super A> transportMapping, Target<A> target,
                                                 PDU pdu, boolean expectResponse) throws MessageException {
        return dispatcher.sendPdu(transportMapping, target, pdu, expectResponse);
    }

    public <A extends Address> PduHandle sendPdu(TransportMapping<? super A> transportMapping, Target<A> target,
                                                 PDU pdu, boolean expectResponse,
                                                 PduHandleCallback<PDU> callback) throws MessageException {
        return dispatcher.sendPdu(transportMapping, target, pdu, expectResponse, callback);
    }

    public <A extends Address> int returnResponsePdu(int messageProcessingModel,
                                 int securityModel,
                                 byte[] securityName,
                                 int securityLevel,
                                 PDU pdu,
                                 int maxSizeResponseScopedPDU,
                                 StateReference<A> stateReference,
                                 StatusInformation statusInformation)
            throws MessageException {
        return dispatcher.returnResponsePdu(messageProcessingModel,
                securityModel, securityName,
                securityLevel, pdu,
                maxSizeResponseScopedPDU,
                stateReference,
                statusInformation);
    }

    public void releaseStateReference(int messageProcessingModel,
                                      PduHandle pduHandle) {
        dispatcher.releaseStateReference(messageProcessingModel, pduHandle);
    }

    @Override
    @Deprecated
    public <A extends Address> TransportMapping<? super A> getTransport(A destAddress) {
        TransportMapping<? super A> transportMapping = getTransport(destAddress, TransportType.receiver);
        if (transportMapping == null) {
            transportMapping = getTransport(destAddress, TransportType.sender);
        }
        return transportMapping;
    }

    @Override
    public <A extends Address> TransportMapping<? super A> getTransport(A destAddress, TransportType transportType) {
        return dispatcher.getTransport(destAddress, transportType);
    }

    public <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport, A incomingAddress,
                                                   ByteBuffer wholeMessage, TransportStateReference tmStateReference) {
        MessageTask<A> task = new MessageTask<>(sourceTransport, incomingAddress, wholeMessage, tmStateReference);
        threadPool.execute(task);
    }

    class MessageTask<A extends Address> implements WorkerTask {
        private final TransportMapping<? super A> sourceTransport;
        private final A incomingAddress;
        private final ByteBuffer wholeMessage;
        private final TransportStateReference tmStateReference;

        public MessageTask(TransportMapping<? super A> sourceTransport,
                           A incomingAddress,
                           ByteBuffer wholeMessage,
                           TransportStateReference tmStateReference) {
            this.sourceTransport = sourceTransport;
            this.incomingAddress = incomingAddress;
            this.wholeMessage = wholeMessage;
            this.tmStateReference = tmStateReference;
        }

        public void run() {
            dispatcher.processMessage(sourceTransport, incomingAddress, wholeMessage, tmStateReference);
        }

        public void terminate() {
        }

        public void join() throws InterruptedException {
        }

        public void interrupt() {
        }

    }

    public void stop() {
        this.threadPool.stop();
    }
}
