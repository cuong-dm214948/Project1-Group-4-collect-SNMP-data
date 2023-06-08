/*_############################################################################
  _## 
  _##  SNMP4J - TableUtils.java  
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

import java.util.*;

import org.snmp4j.log.*;
import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;

import java.io.*;

/**
 * The {@code TableUtils} class provides utility functions to retrieve
 * SNMP tabular data.
 *
 * @author Frank Fock
 * @version 2.5.11
 * @since 1.0.2
 */
public class TableUtils extends AbstractSnmpUtility {

    private static final LogAdapter logger =
            LogFactory.getLogger(TableUtils.class);

    // RowStatus TC enumerated values
    public static final int ROWSTATUS_ACTIVE = 1;
    public static final int ROWSTATUS_NOTINSERVICE = 2;
    public static final int ROWSTATUS_NOTREADY = 3;
    public static final int ROWSTATUS_CREATEANDGO = 4;
    public static final int ROWSTATUS_CREATEANDWAIT = 5;
    public static final int ROWSTATUS_DESTROY = 6;

    private int maxNumOfRowsPerPDU = 10;
    private int maxNumColumnsPerPDU = 10;

    private boolean sendColumnPDUsMultiThreaded;
    private boolean checkLexicographicOrdering = true;
    private int ignoreMaxLexicographicRowOrderingErrors = 3;

    /**
     * Limits the maximum number of rows returned.
     */
    private int rowLimit = 0;

    public enum SparseTableMode {
        sparseTable,
        denseTableDropIncompleteRows,
        denseTableDoubleCheckIncompleteRows
    }

    /**
     * Creates a {@code TableUtils} instance. The created instance is thread
     * safe as long as the supplied {@code Session} and {@code PDUFactory}
     * are thread safe.
     *
     * @param snmpSession
     *         a SNMP {@code Session} instance.
     * @param pduFactory
     *         a {@code PDUFactory} instance that creates the PDU that are used
     *         by this instance to retrieve table data using GETBULK/GETNEXT
     *         operations.
     */
    public TableUtils(Session snmpSession, PDUFactory pduFactory) {
        super(snmpSession, pduFactory);
    }

    /**
     * Gets synchronously SNMP tabular data from one or more tables.
     * The data is returned row-by-row as a list of {@link TableEvent} instances.
     * Each instance represents a row (or an error condition). Besides the
     * target agent, the OIDs of the columnar objects have to be specified
     * for which instances should be retrieved. With a lower bound index and
     * an upper bound index, the result set can be narrowed to improve
     * performance. This method can be executed concurrently by multiple threads.
     *
     * @param target
     *         a {@code Target} instance.
     * @param columnOIDs
     *         an array of OIDs of the columnar objects whose instances should be
     *         retrieved. The columnar objects may belong to different tables.
     *         Typically, they belong to tables that share a common index or sub-index
     *         prefix. Note: The result of this method is not defined if instance OIDs
     *         are supplied in this array!
     * @param lowerBoundIndex
     *         an optional parameter that specifies the lower bound index.
     *         If not {@code null}, all returned rows have an index greater than
     *         {@code lowerBoundIndex}.
     * @param upperBoundIndex
     *         an optional parameter that specifies the upper bound index.
     *         If not {@code null}, all returned rows have an index less or equal
     *         than {@code upperBoundIndex}.
     *
     * @return a {@code List} of {@link TableEvent} instances. Each instance
     * represents successfully retrieved row or an error condition. Error
     * conditions (any status other than {@link TableEvent#STATUS_OK})
     * may only appear at the last element of the list.
     */
    public List<TableEvent> getTable(Target<?> target, OID[] columnOIDs, OID lowerBoundIndex, OID upperBoundIndex) {
        return getTable(target, columnOIDs, lowerBoundIndex, upperBoundIndex, 0);
    }

    /**
     * Gets synchronously SNMP tabular data from one or more tables.
     * The data is returned row-by-row as a list of {@link TableEvent} instances.
     * Each instance represents a row (or an error condition). Besides the
     * target agent, the OIDs of the columnar objects have to be specified
     * for which instances should be retrieved. With a lower bound index and
     * an upper bound index, the result set can be narrowed to improve
     * performance. This method can be executed concurrently by multiple threads.
     *
     * @param target
     *         a {@code Target} instance.
     * @param columnOIDs
     *         an array of OIDs of the columnar objects whose instances should be
     *         retrieved. The columnar objects may belong to different tables.
     *         Typically, they belong to tables that share a common index or sub-index
     *         prefix. Note: The result of this method is not defined if instance OIDs
     *         are supplied in this array!
     * @param lowerBoundIndex
     *         an optional parameter that specifies the lower bound index.
     *         If not {@code null}, all returned rows have an index greater than
     *         {@code lowerBoundIndex}.
     * @param upperBoundIndex
     *         an optional parameter that specifies the upper bound index.
     *         If not {@code null}, all returned rows have an index less or equal
     *         than {@code upperBoundIndex}.
     * @param timeoutSeconds
     *         the maximum number of seconds to wait for the whole table to be retrieved.
     *         Set it to 0, to wait forever.
     *
     * @return a {@code List} of {@link TableEvent} instances. Each instance
     * represents successfully retrieved row or an error condition. Error
     * conditions (any status other than {@link TableEvent#STATUS_OK})
     * may only appear at the last element of the list.
     *
     * @since 3.4.5
     */
    public List<TableEvent> getTable(Target<?> target, OID[] columnOIDs, OID lowerBoundIndex, OID upperBoundIndex,
                                     long timeoutSeconds) {

        if ((columnOIDs == null) || (columnOIDs.length == 0)) {
            throw new IllegalArgumentException("No column OIDs specified");
        }
        InternalTableListener listener = new InternalTableListener();
        TableRequest req = createTableRequest(target, columnOIDs, listener,
                null,
                lowerBoundIndex,
                upperBoundIndex, SparseTableMode.sparseTable);
        synchronized (listener) {
            if (req.sendNextChunk()) {
                try {
                    listener.wait(timeoutSeconds*1000);
                    if (!listener.finished) {
                        listener.finished = true;
                        listener.rows.add(new TableEvent(req, null, TableEvent.STATUS_TIMEOUT));
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        return listener.getRows();
    }

    protected TableRequest createTableRequest(Target<?> target, OID[] columnOIDs, TableListener listener,
                                              Object userObject, OID lowerBoundIndex, OID upperBoundIndex,
                                              SparseTableMode sparseTableMode) {
        return new TableRequest(target, columnOIDs, listener,
                userObject, lowerBoundIndex, upperBoundIndex, sparseTableMode);
    }

    /**
     * Gets SNMP tabular data from one or more tables. The data is returned
     * asynchronously row-by-row through a supplied callback. Besides the
     * target agent, the OIDs of the columnar objects have to be specified
     * for which instances should be retrieved. With a lower bound index and
     * an upper bound index, the result set can be narrowed to improve
     * performance.
     * <p>
     * This method may call the {@link TableListener#finished} method before
     * it returns. If you want to synchronize the main thread with the
     * finishing of the table retrieval, follow this pattern:
     * <pre>
     *      synchronized (this) {
     *         TableListener myListener = ... {
     *            private boolean finished;
     *
     *            public boolean isFinished() {
     *              return finished;
     *            }
     *
     *            public void finished(TableEvent event) {
     *               ..
     *               finished = true;
     *               synchronized (event.getUserObject()) {
     *                  event.getUserObject().notify();
     *               }
     *            }
     *         };
     *         tableUtil.getTable(..,..,myListener,this,..,..);
     *         while (!myListener.isFinished()) {
     *           wait();
     *         }
     *      }
     * </pre>
     *
     * @param target
     *         a {@code Target} instance.
     * @param columnOIDs
     *         an array of OIDs of the columnar objects whose instances should be
     *         retrieved. The columnar objects may belong to different tables.
     *         Typically, they belong to tables that share a common index or sub-index
     *         prefix. Note: The result of this method is not defined if instance OIDs
     *         are supplied in this array!
     * @param listener
     *         a {@code TableListener} that is called with {@link TableEvent}
     *         objects when an error occured, new rows have been retrieved, or when
     *         the table has been retrieved completely.
     * @param userObject
     *         an user object that is transparently supplied to the above call back.
     * @param lowerBoundIndex
     *         an optional parameter that specifies the lower bound index.
     *         If not {@code null}, all returned rows have an index greater than
     *         {@code lowerBoundIndex}.
     * @param upperBoundIndex
     *         an optional parameter that specifies the upper bound index.
     *         If not {@code null}, all returned rows have an index less or equal
     *         than {@code upperBoundIndex}.
     * @param sparseTableMode
     *         defines how rows with non-existing column values should be handled.
     *         Such rows can occur when new rows are being created or rows are removed
     *         from an agent while it is being
     */
    public void getTable(Target<?> target, OID[] columnOIDs, TableListener listener, Object userObject,
                         OID lowerBoundIndex, OID upperBoundIndex, SparseTableMode sparseTableMode) {
        if ((columnOIDs == null) || (columnOIDs.length == 0)) {
            throw new IllegalArgumentException("No column OIDs specified");
        }
        TableRequest req = new TableRequest(target, columnOIDs, listener,
                userObject,
                lowerBoundIndex,
                upperBoundIndex, sparseTableMode);
        boolean sendMore = req.sendNextChunk();
        while (sendColumnPDUsMultiThreaded && sendMore) {
            sendMore = req.sendNextChunk();
        }
    }

    /**
     * Gets SNMP tabular data from one or more tables. The data is returned
     * asynchronously row-by-row through a supplied callback. Besides the
     * target agent, the OIDs of the columnar objects have to be specified
     * for which instances should be retrieved. With a lower bound index and
     * an upper bound index, the result set can be narrowed to improve
     * performance.
     * <p>
     * This method may call the {@link TableListener#finished} method before
     * it returns. If you want to synchronize the main thread with the
     * finishing of the table retrieval, follow this pattern:
     * <pre>
     *      synchronized (this) {
     *         TableListener myListener = ... {
     *            private boolean finished;
     *
     *            public boolean isFinished() {
     *              return finished;
     *            }
     *
     *            public void finished(TableEvent event) {
     *               ..
     *               finished = true;
     *               synchronized (event.getUserObject()) {
     *                  event.getUserObject().notify();
     *               }
     *            }
     *         };
     *         tableUtil.getTable(..,..,myListener,this,..,..);
     *         while (!myListener.isFinished()) {
     *           wait();
     *         }
     *      }
     * </pre>
     *
     * @param target
     *         a {@code Target} instance.
     * @param columnOIDs
     *         an array of OIDs of the columnar objects whose instances should be
     *         retrieved. The columnar objects may belong to different tables.
     *         Typically, they belong to tables that share a common index or sub-index
     *         prefix. Note: The result of this method is not defined if instance OIDs
     *         are supplied in this array!
     * @param listener
     *         a {@code TableListener} that is called with {@link TableEvent}
     *         objects when an error occurred, new rows have been retrieved, or when
     *         the table has been retrieved completely.
     * @param userObject
     *         an user object that is transparently supplied to the above call back.
     * @param lowerBoundIndex
     *         an optional parameter that specifies the lower bound index.
     *         If not {@code null}, all returned rows have an index greater than
     *         {@code lowerBoundIndex}.
     * @param upperBoundIndex
     *         an optional parameter that specifies the upper bound index.
     *         If not {@code null}, all returned rows have an index less or equal
     *         than {@code upperBoundIndex}.
     * @since 1.5
     */
    public void getTable(Target<?> target, OID[] columnOIDs, TableListener listener, Object userObject,
                         OID lowerBoundIndex, OID upperBoundIndex) {
        getTable(target, columnOIDs, listener, userObject, lowerBoundIndex, upperBoundIndex,
                SparseTableMode.sparseTable);
    }

    /**
     * Gets SNMP tabular data from one or more tables. The data is returned
     * asynchronously row-by-row through a supplied callback. Besides the
     * target agent, the OIDs of the columnar objects have to be specified
     * for which instances should be retrieved. With a lower bound index and
     * an upper bound index, the result set can be narrowed to improve
     * performance.
     * <p>
     * This implementation must not be used with sparse tables, because it
     * is optimized for dense tables and will not return correct results for
     * sparse tables.
     * </p>
     * Rows that appear or disappear while being retrieved, are dropped and
     * will be not returned partially (see {@link SparseTableMode#denseTableDropIncompleteRows}).
     *
     * @param target
     *         a {@code Target} instance.
     * @param columnOIDs
     *         an array of OIDs of the columnar objects whose instances should be
     *         retrieved. The columnar objects may belong to different tables.
     *         Typically they belong to tables that share a common index or sub-index
     *         prefix. Note: The result of this method is not defined if instance OIDs
     *         are supplied in this array!
     * @param listener
     *         a {@code TableListener} that is called with {@link TableEvent}
     *         objects when an error occurred, new rows have been retrieved, or when
     *         the table has been retrieved completely.
     * @param userObject
     *         an user object that is transparently supplied to the above call back.
     * @param lowerBoundIndex
     *         an optional parameter that specifies the lower bound index.
     *         If not {@code null}, all returned rows have an index greater than
     *         {@code lowerBoundIndex}.
     * @param upperBoundIndex
     *         an optional parameter that specifies the upper bound index.
     *         If not {@code null}, all returned rows have an index less or equal
     *         than {@code lowerBoundIndex}.
     * @since 3.0
     */
    public void getDenseTable(Target<?> target, OID[] columnOIDs, TableListener listener, Object userObject,
                              OID lowerBoundIndex, OID upperBoundIndex) {
        if ((columnOIDs == null) || (columnOIDs.length == 0)) {
            throw new IllegalArgumentException("No column OIDs specified");
        }
        TableRequest req = new TableRequest(target, columnOIDs, listener,
                userObject,
                lowerBoundIndex,
                upperBoundIndex, SparseTableMode.denseTableDropIncompleteRows);
        req.sendNextChunk();
    }

    /**
     * Gets the maximum number of rows that will be retrieved per SNMP GETBULK
     * request.
     *
     * @return an integer greater than zero that specifies the maximum number of rows
     * to retrieve per SNMP GETBULK operation.
     */
    public int getMaxNumRowsPerPDU() {
        return maxNumOfRowsPerPDU;
    }

    /**
     * Sets the maximum number of rows that will be retrieved per SNMP GETBULK
     * request. The default is 10.
     *
     * @param numberOfRowsPerChunk
     *         an integer greater than zero that specifies the maximum number of rows
     *         to retrieve per SNMP GETBULK operation.
     */
    public void setMaxNumRowsPerPDU(int numberOfRowsPerChunk) {
        if (numberOfRowsPerChunk < 1) {
            throw new IllegalArgumentException(
                    "The number of rows per PDU must be > 0");
        }
        this.maxNumOfRowsPerPDU = numberOfRowsPerChunk;
    }

    /**
     * Gets the maximum number of columns that will be retrieved per SNMP GETNEXT
     * or GETBULK request.
     *
     * @return an integer greater than zero that specifies the maximum columns of rows
     * to retrieve per SNMP GETNEXT or GETBULK operation.
     */
    public int getMaxNumColumnsPerPDU() {
        return maxNumColumnsPerPDU;
    }

    /**
     * Sets the maximum number of columns that will be retrieved per SNMP GETNEXT
     * or GETBULK request. The default is 10.
     *
     * @param numberOfColumnsPerChunk
     *         an integer greater than zero that specifies the maximum columns of rows
     *         to retrieve per SNMP GETNEXT or GETBULK operation.
     */
    public void setMaxNumColumnsPerPDU(int numberOfColumnsPerChunk) {
        if (numberOfColumnsPerChunk < 1) {
            throw new IllegalArgumentException(
                    "The number of columns per PDU must be > 0");
        }
        this.maxNumColumnsPerPDU = numberOfColumnsPerChunk;
    }

    public boolean isSendColumnPDUsMultiThreaded() {
        return sendColumnPDUsMultiThreaded;
    }

    /**
     * Enable multi-threaded column PDU sending. If set to {@code true} and if the {@link #maxNumColumnsPerPDU} value
     * is less than the number of columns to be retrieved in a {@link TableUtils} request, then the requests for the
     * columns will be splitted in two or more columns and the requests will be send to the agent concurrently without
     * waiting for the response of the first/previous PDU. By default, this is disabled.
     *
     * @param sendColumnPDUsMultiThreaded
     *         if {@code true}, multi-threaded processing of column PDUs is enabled, otherwise only a single request
     *         will be sent to the agent on behalf a {@link #getTable(Target, OID[], OID, OID)} or
     *         {@link #getTable(Target, OID[], TableListener, Object, OID, OID)}.
     */
    public void setSendColumnPDUsMultiThreaded(boolean sendColumnPDUsMultiThreaded) {
        this.sendColumnPDUsMultiThreaded = sendColumnPDUsMultiThreaded;
    }

    /**
     * Indicates whether a single request on behalf of {@link #getTable(Target, OID[], OID, OID)} or
     * {@link #getTable(Target, OID[], TableListener, Object, OID, OID)} is sent to the agent or not.
     *
     * @return {@code false} if single requests are sent, {@code true} if more than a single request may be sent at a
     * time.
     */
    public boolean isCheckLexicographicOrdering() {
        return checkLexicographicOrdering;
    }

    /**
     * Gets the maximum number of rows with wrong lexicographic ordering whicb will be return on a table retrieval
     * with {@link #isCheckLexicographicOrdering()} set to {@code true}.
     *
     * @return the number of ignored row ordering errors.
     * @since 2.5.11
     */
    public int getIgnoreMaxLexicographicRowOrderingErrors() {
        return ignoreMaxLexicographicRowOrderingErrors;
    }

    /**
     * Sets the maximum number of rows that will be returned with status {@link TableEvent#STATUS_WRONG_ORDER} before
     * the table retrieval will be stopped. If this value is set to zero and lexicographic ordering check is enabled by
     * {@link #setCheckLexicographicOrdering(boolean)}, then table retrieval finishes immediately when the error is
     * detected. Otherwise, retrieval continues until the maximum errors are detected and then the row cache will be
     * returned too, although it may contain already incomplete rows based on correctly or incorrectly (!) ordered rows.
     * The default value is three. That means, even if the ordering error occurs at the end of the table and
     *
     * @param ignoreMaxLexicographicRowOrderingErrors
     *         the maximum numbers of rows with lexicographic ordering error to be returned before finishing table
     *         retrieve automatically. Setting this value has no effect if {@link #isCheckLexicographicOrdering()}
     *         is {@code false}.
     *
     * @since 2.5.11
     */
    public void setIgnoreMaxLexicographicRowOrderingErrors(int ignoreMaxLexicographicRowOrderingErrors) {
        this.ignoreMaxLexicographicRowOrderingErrors = ignoreMaxLexicographicRowOrderingErrors;
    }

    /**
     * Enables or disables lexicographic ordering checks. By default, those checks are enabled, because otherwise
     * with agents, that do not implement correct lexicographic ordering, endless looping could occur.
     *
     * @param checkLexicographicOrdering
     *         {@code false} to disable checks which could increase performance.
     *
     * @since 2.5.10
     */
    public void setCheckLexicographicOrdering(boolean checkLexicographicOrdering) {
        this.checkLexicographicOrdering = checkLexicographicOrdering;
    }


    protected class ColumnsOfRequest {
        private final List<Integer> columnIDs;
        private final int requestSerial;
        private final LastReceived lastReceived;

        public ColumnsOfRequest(List<Integer> columnIDs, int requestSerial, LastReceived lastReceived) {
            this.columnIDs = columnIDs;
            this.requestSerial = requestSerial;
            this.lastReceived = lastReceived;
        }

        public List<Integer> getColumnIDs() {
            return columnIDs;
        }

        public int getRequestSerial() {
            return requestSerial;
        }

        public LastReceived getLastReceived() {
            return lastReceived;
        }
    }

    public class TableRequest implements ResponseListener {

        Target<?> target;
        OID[] columnOIDs;
        TableListener listener;
        Object userObject;
        OID lowerBoundIndex;
        OID upperBoundIndex;

        private int sent = 0;
        private boolean anyMatch = false;
        private List<OID> lastSent = null;
        private final LinkedList<Row> rowCache = new LinkedList<Row>();
        protected LastReceived lastReceived;
        private int requestSerial = Integer.MIN_VALUE;
        private final List<Integer> requestSerialsPending = Collections.synchronizedList(new LinkedList<Integer>());
        private int numLexicographicErrors = 0;

        volatile boolean finished = false;

        private final SparseTableMode sparseTableMode;

        protected int rowsRetrieved = 0;
        protected int rowsReleased = 0;
        private OID lastMinIndex = null;

        public TableRequest(Target<?> target,
                            OID[] columnOIDs,
                            TableListener listener,
                            Object userObject,
                            OID lowerBoundIndex,
                            OID upperBoundIndex, SparseTableMode sparseTableMode) {
            this.target = target;
            this.columnOIDs = columnOIDs;
            this.listener = listener;
            this.userObject = userObject;
            this.lastReceived = new LastReceived(Arrays.asList(columnOIDs));
            this.upperBoundIndex = upperBoundIndex;
            this.lowerBoundIndex = lowerBoundIndex;
            if (lowerBoundIndex != null) {
                for (int i = 0; i < lastReceived.size(); i++) {
                    OID oid = new OID((lastReceived.get(i)));
                    oid.append(lowerBoundIndex);
                    lastReceived.set(i, oid);
                }
            }
            this.sparseTableMode = sparseTableMode;
        }


        public SparseTableMode getSparseTableMode() {
            return sparseTableMode;
        }

        /**
         * Gets the number of lexicographic errors that occurred during request processing. Any errors occurred on the same
         * row will be count as one error.
         *
         * @return the number of rows returned by the agent in wrong lexicographic order (i.e. not strictly ascending).
         * @since 2.5.11
         */
        public int getNumLexicographicErrors() {
            return numLexicographicErrors;
        }

        public boolean sendNextChunk() {
            if (sent >= lastReceived.size()) {
                return false;
            }
            PDU pdu = pduFactory.createPDU(target);
            if (target.getVersion() == SnmpConstants.version1) {
                pdu.setType(PDU.GETNEXT);
            } else if (pdu.getType() != PDU.GETNEXT) {
                pdu.setType(PDU.GETBULK);
            }
            int sz = Math.min(lastReceived.size() - sent, maxNumColumnsPerPDU);
            if (pdu.getType() == PDU.GETBULK) {
                if (maxNumOfRowsPerPDU > 0) {
                    pdu.setMaxRepetitions(maxNumOfRowsPerPDU);
                    pdu.setNonRepeaters(0);
                } else {
                    pdu.setNonRepeaters(sz);
                    pdu.setMaxRepetitions(0);
                }
            }
            lastSent = new ArrayList<>(sz + 1);
            List<Integer> sentColumns = new ArrayList<Integer>(sz);
            int chunkSize = 0;
            for (int i = sent; i < sent + sz; i++) {
                OID col = lastReceived.get(i);
                // only sent columns that are not complete yet
                if (col.startsWith(columnOIDs[i])) {
                    VariableBinding vb = new VariableBinding(col);
                    pdu.add(vb);
                    if (pdu.getBERLength() > target.getMaxSizeRequestPDU()) {
                        pdu.trim();
                        break;
                    } else {
                        lastSent.add(lastReceived.get(i));
                        chunkSize++;
                    }
                    sentColumns.add(i);
                } else {
                    chunkSize++;
                    // check if rows in cache can be released due to last column finished
                    if (i+1 == columnOIDs.length) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Last column finished, releasing row cache up to index "
                                    + lastMinIndex);
                        }
                        releaseCache(lastMinIndex);
                    }
                }
            }
            try {
                sent += chunkSize;
                if (pdu.size() == 0) {
                    return false;
                }
                ColumnsOfRequest columnsOfRequest = new ColumnsOfRequest(sentColumns, requestSerial++,
                        isCheckLexicographicOrdering() ? new LastReceived(lastReceived) : null);
                sendRequest(pdu, target, columnsOfRequest);
            } catch (Exception ex) {
                logger.error(ex);
                if (logger.isDebugEnabled()) {
                    ex.printStackTrace();
                }
                listener.finished(new TableEvent(this, userObject, ex));
                return false;
            }
            return true;
        }

        protected void sendRequest(PDU pdu, Target<?> target, ColumnsOfRequest sendColumns)
                throws IOException {
            requestSerialsPending.add(sendColumns.getRequestSerial());
            session.send(pdu, target, sendColumns, this);
        }

        protected synchronized boolean removePending(int requestSerial) {
            boolean inOrder = true;
            for (Iterator<Integer> it = requestSerialsPending.iterator(); it.hasNext(); ) {
                int pendingRequestSerial = it.next();
                if (pendingRequestSerial == requestSerial) {
                    it.remove();
                } else {
                    inOrder = false;
                }
            }
            return inOrder;
        }

        @SuppressWarnings("unchecked")
        public <A extends Address> void onResponse(ResponseEvent<A> event) {
            // Do not forget to cancel the asynchronous request! ;-)
            session.cancel(event.getRequest(), this);
            if (finished) {
                return;
            }
            synchronized (this) {
                if (checkResponse(event)) {
                    boolean anyMatchInChunk = false;
                    ColumnsOfRequest colsOfRequest = (ColumnsOfRequest) event.getUserObject();
                    boolean receivedInOrder = removePending(colsOfRequest.getRequestSerial());
                    PDU request = event.getRequest();
                    PDU response = event.getResponse();
                    int cols = request.size();
                    int rows = response.size() / cols;
                    OID nextMinIndex = null;
                    for (int r = 0; r < rows; r++) {
                        Row row = null;
                        anyMatchInChunk = false;
                        for (int c = 0; c < cols; c++) {
                            int pos = colsOfRequest.getColumnIDs().get(c);
                            VariableBinding vb = response.get(r * cols + c);
                            if (vb.isException()) {
                                continue;
                            }
                            OID id = vb.getOid();
                            OID col = columnOIDs[pos];
                            if (id.startsWith(col)) {
                                OID index = new OID(id.getValue(), col.size(), id.size() - col.size());
                                if ((upperBoundIndex != null) && (index.compareTo(upperBoundIndex) > 0)) {
                                    continue;
                                }
                                if ((nextMinIndex == null) || (index.compareTo(nextMinIndex) < 0)) {
                                    nextMinIndex = index;
                                }
                                anyMatchInChunk = true;
                                if ((row == null) || (!row.getRowIndex().equals(index))) {
                                    row = null;
                                    row = getRowFromCache(row, index);
                                }
                                if (row == null) {
                                    row = new Row(index);
                                    appendOrInsertNewRowToCache(row, index);
                                    rowsRetrieved++;
                                }
                                row.setNumComplete(pos);
                                if (pos < row.getNumComplete()) {
                                    row.set(pos, vb);
                                } else {
                                    row.add(vb);
                                }
                                if (isCheckLexicographicOrdering()) {
                                    OID requested = event.getRequest().get(c).getOid();
                                    if (id.compareTo(requested) <= 0) {
                                        if (!row.orderError) {
                                            row.orderError = true;
                                        }
                                    } else if (colsOfRequest.lastReceived != null) {
                                        try {
                                            Row baseRow = colsOfRequest.lastReceived.getColumnInfos().get(pos).getBasedOn();
                                            if (baseRow != null && baseRow.isOrderError()) {
                                                row.orderError = true;
                                            }
                                        } catch (Exception ex) {
                                            // ignore
                                        }
                                    }
                                    // check if current row is based on a wrong order row and mark it too
                                }
                                lastReceived.set(pos, vb.getOid(), row);
                            } else {
                                lastReceived.set(pos, vb.getOid());
                            }
                        }
                    }
                    if (getRowLimit() > 0 && rowsRetrieved >= getRowLimit()) {
                        for (int i=rowsRetrieved - getRowLimit(); i>0 && !rowCache.isEmpty(); i--) {
                            TableUtils.Row lastRow = rowCache.removeLast();
                            if (logger.isDebugEnabled()) {
                                logger.debug("Removing off limit row from cache with index = "+lastRow.index);
                            }
                        }
                        finishRequest(TableEvent.STATUS_ROW_LIMIT_REACHED);
                        return;
                    }
                    anyMatch |= anyMatchInChunk;
                    lastMinIndex = nextMinIndex;
                    Row firstCacheRow;
                    while (((firstCacheRow = (rowCache.isEmpty()) ? null : rowCache.getFirst()) != null) &&
                            (firstCacheRow.getNumComplete() == columnOIDs.length) &&
                            // make sure, row is not prematurely deemed complete
                            (receivedInOrder) &&
                            ((sparseTableMode == SparseTableMode.sparseTable) || (!firstCacheRow.hasNullValues())) &&
                            ((lastMinIndex == null) || firstCacheRow.orderError ||
                                    (firstCacheRow.getRowIndex().compareTo(nextMinIndex) < 0))) {
                        TableEvent tableEvent = getNextTableEvent();
                        rowsReleased++;
                        if (isCheckLexicographicOrdering() &&
                                (tableEvent != null && tableEvent.status == TableEvent.STATUS_WRONG_ORDER &&
                                        numLexicographicErrors >= ignoreMaxLexicographicRowOrderingErrors)) {
                            if (ignoreMaxLexicographicRowOrderingErrors > 0) {
                                listener.next(tableEvent);
                            }
                            finishRequest(TableEvent.STATUS_WRONG_ORDER);
                            return;
                        } else if (tableEvent == null || !listener.next(tableEvent)) {
                            finishRequest(getTableStatus());
                            return;
                        }
                    }
                    if (sparseTableMode == SparseTableMode.denseTableDoubleCheckIncompleteRows &&
                            firstCacheRow != null &&
                            firstCacheRow.hasNullValues()) {
                        ResponseListener responseListener = new ResponseListener() {
                            @Override
                            public <A extends Address> void onResponse(ResponseEvent<A> event) {
                                Row cachedRow = (Row) event.getUserObject();
                                if (event.getResponse() !=  null && event.getResponse().getErrorStatus() == PDU.noError) {
                                    for (VariableBinding vb : event.getResponse().getVariableBindings()) {
                                        if (!vb.isException()) {
                                            for (int i=0; i<columnOIDs.length; i++) {
                                                if (vb.getOid().startsWith(columnOIDs[i])) {
                                                    cachedRow.set(i, vb);
                                                    if (logger.isDebugEnabled()) {
                                                        logger.debug("Received column " + i +
                                                                " for recently appeared row "+cachedRow.index+
                                                                " with GET request: " + vb +
                                                                ", row.firstNullValueIndex="+cachedRow.firstNullValue);
                                                    }
                                                }
                                            }
                                        }
                                        else if (logger.isDebugEnabled()) {
                                            logger.debug("Row "+cachedRow.index+" has been removed because "+
                                                    vb+" returned exception");
                                        }
                                    }
                                }
                                else if (event.getResponse() == null) {
                                    finishRequest(TableEvent.STATUS_TIMEOUT);
                                }
                                else {
                                    finishRequest(event.getResponse().getErrorStatus());
                                }
                            }
                        };
                        PDU pdu = pduFactory.createPDU(target);
                        pdu.setType(PDU.GET);
                        for (int i=0; i<firstCacheRow.size(); i++) {
                            if (firstCacheRow.get(i) == null) {
                                OID colOID = new OID(columnOIDs[i].getValue(), firstCacheRow.index.getValue());
                                pdu.add(new VariableBinding(colOID));
                            }
                            if (pdu.size() >= maxNumColumnsPerPDU) {
                                pdu = sendGetPDU(firstCacheRow, responseListener, pdu);
                            }
                        }
                        if (pdu.size() > 0) {
                            sendGetPDU(firstCacheRow, responseListener, pdu);
                        }
                    }
                    if (receivedInOrder) {
                        boolean sentChunk;
                        if (!(sentChunk = sendNextChunk())) {
                            if (anyMatch) {
                                sent = 0;
                                anyMatch = false;
                                sentChunk = sendNextChunk();
                            }
                            if (!sentChunk) {
                                finishRequest(getTableStatus());
                            }
                        }
                    }
                }
            }
        }

        private void appendOrInsertNewRowToCache(Row row, OID index) {
            if (rowCache.size() == 0) {
                rowCache.add(row);
            } else if ((rowCache.getFirst()).getRowIndex().compareTo(index) >= 0) {
                rowCache.addFirst(row);
            } else {
                insertRowIntoCache(row, index);
            }
        }

        private void insertRowIntoCache(Row row, OID index) {
            for (ListIterator<Row> it = rowCache.listIterator(rowCache.size());
                 it.hasPrevious(); ) {
                Row lastRow = it.previous();
                if (index.compareTo(lastRow.index) >= 0) {
                    it.set(row);
                    it.add(lastRow);
                    break;
                }
            }
        }

        private Row getRowFromCache(Row row, OID index) {
            for (ListIterator<Row> it = rowCache.listIterator(rowCache.size());
                 it.hasPrevious(); ) {
                Row lastRow = it.previous();
                int compareResult = index.compareTo(lastRow.getRowIndex());
                if (compareResult == 0) {
                    row = lastRow;
                    break;
                } else if (compareResult > 0) {
                    break;
                }
            }
            return row;
        }

        private void finishRequest(int tableEventStatus) {
            releaseCache();
            finished = true;
            listener.finished(new TableEvent(this, userObject,
                    tableEventStatus));
        }

        protected PDU sendGetPDU(Row firstCacheRow, ResponseListener responseListener, PDU pdu) {
            try {
                session.send(pdu, target, firstCacheRow, responseListener);
                pdu = pduFactory.createPDU(target);
                pdu.setType(PDU.GET);
            } catch (IOException e) {
                logger.error(e);
            }
            return pdu;
        }

        protected int getTableStatus() {
            return numLexicographicErrors > 0 ? TableEvent.STATUS_WRONG_ORDER : TableEvent.STATUS_OK;
        }

        protected <A extends Address> boolean checkResponse(ResponseEvent<A> event) {
            if (finished) {
                return false;
            }
            else if (event.getError() != null) {
                finished = true;
                releaseCache();
                listener.finished(new TableEvent(this, userObject, event.getError()));
            } else if (event.getResponse() == null) {
                finished = true;
                // timeout
                releaseCache();
                listener.finished(new TableEvent(this, userObject,
                        TableEvent.STATUS_TIMEOUT));
            } else if (event.getResponse().getType() == PDU.REPORT) {
                finished = true;
                releaseCache();
                listener.finished(new TableEvent(this, userObject,
                        event.getResponse()));
            } else if (event.getResponse().getErrorStatus() != PDU.noError) {
                finished = true;
                releaseCache();
                listener.finished(new TableEvent(this, userObject,
                        event.getResponse().getErrorStatus()));
            } else {
                return true;
            }
            return false;
        }

        /**
         * Release cache to {@link TableListener} up to given index (not-including).
         * @param upperBoundIndex
         *    the upper bound (if not {@code null}) up to which row cache should be released to
         *    the listener. A row with the given index (or greater) will not be release.
         * @since 3.7.4
         */
        private void releaseCache(OID upperBoundIndex) {
            while (rowCache.size() > 0 &&
                    (upperBoundIndex == null ||
                            upperBoundIndex.compareTo(rowCache.getFirst().index) > 0)) {
                TableEvent tableEvent = getNextTableEvent();
                if (tableEvent == null) {
                    continue;
                }
                if (tableEvent.getStatus() != TableEvent.STATUS_WRONG_ORDER ||
                        numLexicographicErrors <= ignoreMaxLexicographicRowOrderingErrors) {
                    rowsReleased++;
                    if (!listener.next(tableEvent)) {
                        break;
                    }
                }
            }
        }

        private void releaseCache() {
            releaseCache(null);
        }

        private TableEvent getNextTableEvent() {
            if (rowCache.isEmpty()) {
                return null;
            }
            Row r = rowCache.removeFirst();
            r.setNumComplete(columnOIDs.length);
            while (sparseTableMode != SparseTableMode.sparseTable &&
                    r.hasNullValues() && !rowCache.isEmpty()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("TableUtils dropped incomplete row " + r + " because mode is " + sparseTableMode);
                }
                try {
                    r = rowCache.removeFirst();
                    r.setNumComplete(columnOIDs.length);
                }
                catch (NoSuchElementException nsee) {
                    // ignore
                }
            }
            VariableBinding[] vbs = new VariableBinding[r.size()];
            vbs = r.toArray(vbs);
            TableEvent tableEvent = new TableEvent(this, userObject, r.getRowIndex(), vbs);
            if (r.isOrderError()) {
                tableEvent.status = TableEvent.STATUS_WRONG_ORDER;
                numLexicographicErrors++;
            }
            return tableEvent;
        }

        public Row getRow(OID index) {
            for (ListIterator<Row> it = rowCache.listIterator(rowCache.size() + 1);
                 it.hasPrevious(); ) {
                Row r = it.previous();
                if (index.equals(r.getRowIndex())) {
                    return r;
                }
            }
            return null;
        }
    }

    /**
     * The {@code DenseTableRequest} extends TableRequest to implement a
     * faster table retrieval than the original. Caution:
     * This version does not correctly retrieve sparse tables!
     *
     * @author Frank Fock
     * @since 1.5
     */
    protected class DenseTableRequest extends TableRequest {
        protected DenseTableRequest(Target<?> target,
                                    OID[] columnOIDs,
                                    TableListener listener,
                                    Object userObject,
                                    OID lowerBoundIndex,
                                    OID upperBoundIndex) {
            super(target, columnOIDs, listener, userObject, lowerBoundIndex,
                    upperBoundIndex, SparseTableMode.denseTableDropIncompleteRows);
        }

        public synchronized <A extends Address> void onResponse(ResponseEvent<A> event) {
            // Do not forget to cancel the asynchronous request! ;-)
            session.cancel(event.getRequest(), this);
            if (finished) {
                return;
            }
            if (checkResponse(event)) {
                int startCol = (Integer) event.getUserObject();
                PDU request = event.getRequest();
                PDU response = event.getResponse();
                int cols = request.size();
                int rows = response.size() / cols;
                OID lastMinIndex = null;
                for (int r = 0; r < rows; r++) {
                    Row row = null;
                    for (int c = 0; c < request.size(); c++) {
                        int pos = startCol + c;
                        VariableBinding vb = response.get(r * cols + c);
                        if (vb.isException()) {
                            continue;
                        }
                        OID id = vb.getOid();
                        OID col = columnOIDs[pos];
                        if (id.startsWith(col)) {
                            OID index =
                                    new OID(id.getValue(), col.size(), id.size() - col.size());
                            if ((upperBoundIndex != null) &&
                                    (index.compareTo(upperBoundIndex) > 0)) {
                                continue;
                            }
                            if ((lastMinIndex == null) ||
                                    (index.compareTo(lastMinIndex) < 0)) {
                                lastMinIndex = index;
                            }
                            if (row == null) {
                                row = new Row(index);
                                super.rowsRetrieved++;
                            }
                            row.setNumComplete(pos);
                            if (pos < row.getNumComplete()) {
                                row.set(pos, vb);
                            } else {
                                row.add(vb);
                            }
                            lastReceived.set(pos, vb.getOid());
                        }
                    }
                    if (row != null) {
                        if (!listener.next(new TableEvent(this, userObject, row.getRowIndex(),
                                row.toArray(new VariableBinding[0])))) {
                            finished = true;
                            listener.finished(new TableEvent(this, userObject));
                            return;
                        }
                    }
                }
                if (!sendNextChunk()) {
                    finished = true;
                    listener.finished(new TableEvent(this, userObject));
                }
            }
        }
    }

    /**
     * Creates an SNMP table row for a table that supports the RowStatus
     * mechanism for row creation.
     *
     * @param target
     *         the Target SNMP entity for the operation.
     * @param rowStatusColumnOID
     *         the column OID of the RowStatus column (without any instance identifier).
     * @param rowIndex
     *         the OID denoting the index of the table row to create.
     * @param values
     *         the values of columns to set in the row. If {@code values} is
     *         {@code null} the row is created via the tripple mode row creation
     *         mechanism (RowStatus is set to createAndWait). Otherwise, each variable
     *         binding has to contain the OID of the columnar object ID (without any
     *         instance identifier) and its value. On return, the variable bindings
     *         will be modified so that the variable binding OIDs will contain the
     *         instance OIDs of the respective columns (thus column OID + rowIndex).
     * @param <A> type of the target {@link Address}
     *
     * @return ResponseEvent
     * the ResponseEvent instance returned by the SNMP session on response
     * of the internally sent SET request. If {@code null}, an IO
     * exception has occurred. Otherwise, if the response PDU is
     * {@code null} a timeout has occurred. Otherwise, check the error
     * status for {@link SnmpConstants#SNMP_ERROR_SUCCESS} to verify that the
     * row creation was successful.
     * @since 1.6
     */
    public <A extends Address> ResponseEvent<A> createRow(Target<A> target, OID rowStatusColumnOID, OID rowIndex,
                                                          VariableBinding[] values) {
        PDU pdu = pduFactory.createPDU(target);
        OID rowStatusID = new OID(rowStatusColumnOID);
        rowStatusID.append(rowIndex);
        VariableBinding rowStatus = new VariableBinding(rowStatusID);
        if (values != null) {
            // one-shot mode
            rowStatus.setVariable(new Integer32(ROWSTATUS_CREATEANDGO));
        } else {
            rowStatus.setVariable(new Integer32(ROWSTATUS_CREATEANDWAIT));
        }
        pdu.add(rowStatus);
        if (values != null) {
            // append index to all columnar values
            for (VariableBinding value : values) {
                OID columnOID = new OID(value.getOid());
                columnOID.append(rowIndex);
                value.setOid(columnOID);
            }
            pdu.addAll(values);
        }
        pdu.setType(PDU.SET);
        try {
            return session.send(pdu, target);
        } catch (IOException ex) {
            logger.error(ex);
        }
        return null;
    }

    /**
     * Destroys an SNMP table row from a table that support the RowStatus
     * mechanism for row creation/deletion.
     *
     * @param target
     *         the Target SNMP entity for the operation.
     * @param rowStatusColumnOID
     *         the column OID of the RowStatus column (without any instance identifier).
     * @param rowIndex
     *         the OID denoting the index of the table row to destroy.
     * @param <A> address type of the target.
     *
     * @return ResponseEvent
     * the ResponseEvent instance returned by the SNMP session on response
     * of the internally sent SET request. If {@code null}, an IO
     * exception has occurred. Otherwise, if the response PDU is
     * {@code null} a timeout has occurred, Otherwise, check the error
     * status for {@link SnmpConstants#SNMP_ERROR_SUCCESS} to verify that the
     * row creation was successful.
     * @since 1.7.6
     */
    public <A extends Address> ResponseEvent<A> destroyRow(Target<A> target, OID rowStatusColumnOID, OID rowIndex) {
        PDU pdu = pduFactory.createPDU(target);
        OID rowStatusID = new OID(rowStatusColumnOID);
        rowStatusID.append(rowIndex);
        VariableBinding rowStatus = new VariableBinding(rowStatusID);
        rowStatus.setVariable(new Integer32(ROWSTATUS_DESTROY));
        pdu.add(rowStatus);
        pdu.setType(PDU.SET);
        try {
            ResponseEvent<A> responseEvent = session.send(pdu, target);
            return responseEvent;
        } catch (IOException ex) {
            logger.error(ex);
        }
        return null;
    }

    /**
     * Gets the current row limit. A value greater than zero limits the total number of row events
     * ({@link TableEvent} to the given number. See {@link #setRowLimit(int)} for details.
     * @return
     *    the row limit.
     * @since 3.7.4
     */
    public int getRowLimit() {
        return rowLimit;
    }

    /**
     * Sets the maximum number of rows returned from the target when {@link #getTable(Target, OID[], OID, OID)} or
     * any other overloaded variants of it are called. Please note, that the last rows returned up to
     * {@link #getMaxNumRowsPerPDU()} might not be complete (i.e., not all columns with data in the agent might have
     * corresponding {@link VariableBinding}s in the returned {@link TableEvent}. This can happen only for sparse
     * tables, where not all columns of a row have values.
     * @param rowLimit
     *    a value greater than zero limits the total number of rows returned. If the limit is reached and probably
     *    more rows would have been available the {@link TableEvent#STATUS_ROW_LIMIT_REACHED} is returned.
     * @since 3.7.4
     */
    public void setRowLimit(int rowLimit) {
        this.rowLimit = rowLimit;
    }

    protected class LastReceived {

        private List<LastReceivedColumnInfo> columnInfos;

        public LastReceived(LastReceived otherLastReceived) {
            this.columnInfos = new ArrayList<LastReceivedColumnInfo>(otherLastReceived.size());
            for (LastReceivedColumnInfo columnInfo : otherLastReceived.columnInfos) {
                this.columnInfos.add(columnInfo);
            }
        }

        public LastReceived(List<OID> plainColumnInfos) {
            this.columnInfos = new ArrayList<>(plainColumnInfos.size());
            for (OID columnOID : plainColumnInfos) {
                columnInfos.add(new LastReceivedColumnInfo(columnOID, null));
            }
        }

        public void setColumnInfos(List<LastReceivedColumnInfo> columnInfos) {
            this.columnInfos = columnInfos;
        }

        public List<LastReceivedColumnInfo> getColumnInfos() {
            return columnInfos;
        }

        public int size() {
            return columnInfos.size();
        }

        public OID get(int i) {
            return columnInfos.get(i).getOid();
        }

        public void set(int i, OID oid) {
            columnInfos.set(i, new LastReceivedColumnInfo(oid, null));
        }

        public void set(int i, OID oid, Row baseRow) {
            columnInfos.set(i, new LastReceivedColumnInfo(oid, baseRow));
        }

        @Override
        public String toString() {
            return "LastReceived{" +
                    "columnInfos=" + columnInfos +
                    '}';
        }
    }

    protected class LastReceivedColumnInfo {
        private OID oid;
        private Row basedOn;

        public LastReceivedColumnInfo(OID oid, Row basedOn) {
            this.oid = oid;
            this.basedOn = basedOn;
        }

        public OID getOid() {
            return oid;
        }

        public Row getBasedOn() {
            return basedOn;
        }

        @Override
        public String toString() {
            return "LastReceivedColumnInfo{" +
                    "oid=" + oid +
                    ", basedOn=" + basedOn +
                    '}';
        }
    }

    protected class Row extends ArrayList<VariableBinding> {

        private static final long serialVersionUID = -2297277440117636627L;

        private OID index;
        private boolean orderError;
        private int firstNullValue = -1;

        public Row(OID index) {
            super();
            this.index = index;
        }

        public boolean isOrderError() {
            return orderError;
        }

        public OID getRowIndex() {
            return index;
        }

        public int getNumComplete() {
            return super.size();
        }

        /**
         * Sets the number of columns in the row cache to a new value. If the number of columns provided is greater than
         * the number of values in the cache, then columns with {@code null} value are appended to the cache to fill
         * up the columns until the specified one.
         *
         * @param numberOfColumnsComplete
         *    the number of columns received already.
         * @return
         *    the number of columns added to the row with {@code null} values.
         */
        public int setNumComplete(int numberOfColumnsComplete) {
            int startSize = getNumComplete();
            int newSize = numberOfColumnsComplete - startSize;
            for (int i = 0; i < newSize; i++) {
                super.add(null);
            }
            if (newSize>0) {
                firstNullValue = startSize;
            }
            return newSize;
        }

        public boolean hasNullValues() {
            return firstNullValue >= 0 && firstNullValue < size();
        }

        @Override
        public VariableBinding set(int index, VariableBinding element) {
            VariableBinding newVB = super.set(index, element);
            if ((firstNullValue == index) && (element != null)) {
                while (firstNullValue < size() && get(firstNullValue) != null) {
                    firstNullValue++;
                }
                if (firstNullValue >= size()) {
                    firstNullValue = -1;
                }
            }
            return newVB;
        }
    }

    protected class InternalTableListener implements TableListener {

        private List<TableEvent> rows = new LinkedList<>();
        private volatile boolean finished = false;

        public boolean next(TableEvent event) {
            rows.add(event);
            return true;
        }

        public synchronized void finished(TableEvent event) {
            if ((event.getStatus() != TableEvent.STATUS_OK) || (event.getIndex() != null)) {
                rows.add(event);
            }
            finished = true;
            notify();
        }

        public List<TableEvent> getRows() {
            return rows;
        }

        public boolean isFinished() {
            return finished;
        }
    }
}
