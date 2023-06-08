/*_############################################################################
  _## 
  _##  SNMP4J - LogAdapter.java  
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


package org.snmp4j.log;

import java.io.Serializable;
import java.util.Iterator;

/**
 * The {@code LogAdapter} specifies the logging interface used by
 * SNMP4J. To provide another logging mechanism as the default no-logging
 * the static method {@link LogFactory#setLogFactory} can be used to assign
 * a different logging adapter factory.
 *
 * @author Frank Fock
 * @version 3.4.1
 * @since 1.2.1
 */
public interface LogAdapter {

    /**
     * Checks whether DEBUG level logging is activated for this log adapter.
     *
     * @return {@code true} if logging is enabled or {@code false} otherwise.
     */
    boolean isDebugEnabled();

    /**
     * Checks whether INFO level logging is activated for this log adapter.
     *
     * @return {@code true} if logging is enabled or {@code false} otherwise.
     */
    boolean isInfoEnabled();

    /**
     * Checks whether WARN level logging is activated for this log adapter.
     *
     * @return {@code true} if logging is enabled or {@code false} otherwise.
     */
    boolean isWarnEnabled();

    /**
     * Logs a debug message.
     *
     * @param message
     *         the message to log.
     */
    void debug(Serializable message);

    /**
     * Logs an informational message.
     *
     * @param message
     *         the message to log.
     */
    void info(CharSequence message);

    /**
     * Logs an warning message.
     *
     * @param message
     *         the message to log.
     */
    void warn(Serializable message);

    /**
     * Logs an error message.
     *
     * @param message
     *         the message to log.
     */
    void error(Serializable message);

    /**
     * Logs an error message.
     *
     * @param message
     *         the message to log.
     * @param throwable
     *         the exception that caused to error.
     */
    void error(CharSequence message, Throwable throwable);

    /**
     * Logs a fatal message.
     *
     * @param message
     *         the message to log.
     */
    void fatal(Object message);

    /**
     * Logs a fatal message.
     *
     * @param message
     *         the message to log.
     * @param throwable
     *         the exception that caused to error.
     */
    void fatal(CharSequence message, Throwable throwable);

    /**
     * Log a message with the specified level.
     * @param logLevel
     *         the level at which the message will be logged.
     * @param message
     *         the message to log.
     * @param throwable
     *         an optional exception associated with the log event.
     */
    default void log(LogLevel logLevel, CharSequence message, Throwable throwable) {
        if (isLogLevelEnabled(logLevel)) {
            switch (logLevel.getLevel()) {
                case LogLevel.LEVEL_DEBUG:
                    debug((Serializable) message);
                    break;
                case LogLevel.LEVEL_INFO:
                    info(message);
                    break;
                    /*
                case LogLevel.LEVEL_TRACE:
                    trace(message);
                    break;
                     */
                case LogLevel.LEVEL_WARN:
                    warn((Serializable) message);
                    break;
                case LogLevel.LEVEL_ERROR:
                    error(message, throwable);
                    break;
            }
        }
    }

    /**
     * Checks whether there is logging enabled for the specified log level for this log adapter.
     * @param logLevel
     *         the level at which the message will be logged.
     * @return
     *         {@code true} if logging is enabled for the specified {@code logLevel}.
     * @since 3.4.1
     */
    default boolean isLogLevelEnabled(LogLevel logLevel) {
        switch (logLevel.getLevel()) {
            case LogLevel.LEVEL_DEBUG:
                return isDebugEnabled();
            case LogLevel.LEVEL_INFO:
                return isInfoEnabled();
//            case LogLevel.LEVEL_TRACE:
//                return isRraceEnabled();
            case LogLevel.LEVEL_WARN:
                return isWarnEnabled();
            case LogLevel.LEVEL_ERROR:
                return getEffectiveLogLevel() != LogLevel.OFF;
        }
        return false;
    }

    /**
     * Sets the log level for this log adapter (if applicable).
     *
     * @param level
     *         a LogLevel instance.
     *
     * @since 1.6.1
     */
    void setLogLevel(LogLevel level);

    /**
     * Returns the log level defined for this log adapter.
     *
     * @return a LogLevel instance.
     * @since 1.6.1
     */
    LogLevel getLogLevel();

    /**
     * Returns the log level that is effective for this log adapter.
     * The effective log level is the first log level different from
     * {@link LogLevel#NONE} to the root.
     *
     * @return a LogLevel different than {@link LogLevel#NONE}.
     * @since 1.6.1
     */
    LogLevel getEffectiveLogLevel();

    /**
     * Returns the name of the logger.
     *
     * @return the name of the logger.
     */
    String getName();

    /**
     * Returns the log handlers associated with this logger.
     *
     * @return an Iterator of log system dependent log handlers.
     * @since 1.6.1
     */
    Iterator<?> getLogHandler();

    /**
     * Remove all log handlers from this log adapter.
     * @since 3.4.1
     */
    default void removeAllHandlers() { }

    /**
     * Sets the log handler reference list associated by this logger.
     * @param logHandlerList
     *    a comma separated list of class names or other log handler IDs.
     * @since 3.4.1
     */
    default void setLogHandler(String logHandlerList) { }
}
