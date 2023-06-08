/*_############################################################################
  _## 
  _##  SNMP4J - BERInputStream.java  
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
package org.snmp4j.asn1;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.BufferUnderflowException;


/**
 * The {@code BERInputStream} class wraps a {@code ByteBuffer} and
 * implements the {@code InputStream} abstract class.
 * positions in the input stream.
 *
 * @author Frank Fock
 * @version 1.6.1
 */

public class BERInputStream extends InputStream {

  private ByteBuffer buffer;

  public BERInputStream(ByteBuffer buffer) {
    this.buffer = buffer;
    buffer.mark();
  }

  public ByteBuffer getBuffer() {
    return buffer;
  }

  public void setBuffer(ByteBuffer buf) {
    this.buffer = buf;
  }

  public int read() throws java.io.IOException {
    try {
      return (buffer.get() & 0xFF);
    }
    catch (BufferUnderflowException ex) {
      throw new IOException("Unexpected end of input stream at position "+
                            getPosition());
    }
  }

  /**
   * Returns the number of bytes that can be read (or skipped over) from this
   * input stream without blocking by the next caller of a method for this input
   * stream.
   *
   * @return the number of bytes that can be read from this input stream without
   *   blocking.
   * @throws IOException if an I/O error occurs.
   */
  public int available() throws IOException {
    return buffer.remaining();
  }

  /**
   * Closes this input stream and releases any system resources associated with
   * the stream.
   *
   * @throws IOException if an I/O error occurs.
   */
  public void close() throws IOException {
  }

  /**
   * Marks the current position in this input stream.
   *
   * @param readlimit the maximum limit of bytes that can be read before the
   *   mark position becomes invalid.
   */
  public synchronized void mark(int readlimit) {
    buffer.mark();
  }

  /**
   * Tests if this input stream supports the {@code mark} and
   * {@code reset} methods.
   *
   * @return {@code true} if this stream instance supports the mark and
   *   reset methods; {@code false} otherwise.
   */
  public boolean markSupported() {
    return true;
  }

  /**
   * Reads some number of bytes from the input stream and stores them into the
   * buffer array {@code b}.
   *
   * @param b the buffer into which the data is read.
   * @return the total number of bytes read into the buffer, or {@code -1}
   *   is there is no more data because the end of the stream has been reached.
   * @throws IOException if an I/O error occurs.
   */
  public int read(byte[] b) throws IOException {
    if (buffer.remaining() <= 0) {
      return -1;
    }
    int read = Math.min(buffer.remaining(), b.length);
    buffer.get(b, 0, read);
    return read;
  }

  /**
   * Reads up to {@code len} bytes of data from the input stream into an
   * array of bytes.
   *
   * @param b the buffer into which the data is read.
   * @param off the start offset in array {@code b} at which the data is
   *   written.
   * @param len the maximum number of bytes to read.
   * @return the total number of bytes read into the buffer, or {@code -1}
   *   if there is no more data because the end of the stream has been reached.
   * @throws IOException if an I/O error occurs.
   */
  public int read(byte[] b, int off, int len) throws IOException {
    if (buffer.remaining() <= 0 && (len > 0)) {
      return -1;
    }
    int read = Math.min(buffer.remaining(), b.length);
    buffer.get(b, off, len);
    return read;
  }

  /**
   * Repositions this stream to the position at the time the {@code mark}
   * method was last called on this input stream.
   *
   * @throws IOException if this stream has not been marked or if the mark has
   *   been invalidated.
   */
  public synchronized void reset() throws IOException {
    buffer.reset();
  }

  /**
   * Skips over and discards {@code n} bytes of data from this input stream.
   *
   * @param n the number of bytes to be skipped.
   * @return the actual number of bytes skipped.
   * @throws IOException if an I/O error occurs.
   */
  public long skip(long n) throws IOException {
    long skipped = Math.min(buffer.remaining(), n);
    buffer.position((int)(buffer.position() + skipped));
    return skipped;
  }

  /**
   * Gets the current position in the underlying {@code buffer}.
   * @return
   *    {@code buffer.position()}.
   */
  public long getPosition() {
    return buffer.position();
  }

  /**
   * Checks whether a mark has been set on the input stream. This can be used
   * to determine whether the value returned by {@link #available()} is limited
   * by a readlimit set when the mark has been set.
   * @return
   *    always {@code true}. If no mark has been set explicitly, the mark
   *    is set to the initial position (i.e. zero).
   */
  public boolean isMarked() {
    return true;
  }

  /**
   * Gets the total number of bytes that can be read from this input stream.
   * @return
   *    the number of bytes that can be read from this stream.
   */
  public int getAvailableBytes() {
    return buffer.limit();
  }

}
