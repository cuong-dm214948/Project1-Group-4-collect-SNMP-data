/*_############################################################################
  _## 
  _##  SNMP4J - LogFactory.java  
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

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The {@code LogFactory} singleton is used by SNMP4J to determine
 * the logging framework used to process SNMP4J log messages. By default
 * {@link NoLogger} instances are used.
 *
 * @author Frank Fock
 * @version 3.4.1
 * @since 1.2.1
 */
public class LogFactory {

    public static final String SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY = "snmp4j.LogFactory";
    public static final String SNMP4J_LOG_FACTORY_LOGGER_DEFAULT_PREFIX = "snmp4j.log.logger.";
    public static final String SNMP4J_LOG_FACTORY_LOG_HANDLER_DEFAULT_PREFIX = "snmp4j.log.handler.";
    public static final String SNMP4J_LOG_ID = "id";
    public static final String SNMP4J_LOG_LEVEL = "level";
    public static final String SNMP4J_LOG_HANDLER = "handler";
    public static final String SNMP4J_LOG_HANDLER_LIST = "handlers";

    private static LogFactory snmp4jLogFactory = null;
    private static boolean configChecked = false;

    private String loggerConfigPrefix = SNMP4J_LOG_FACTORY_LOGGER_DEFAULT_PREFIX;
    private String logHandlerConfigPrefix = SNMP4J_LOG_FACTORY_LOG_HANDLER_DEFAULT_PREFIX;
    private final ReentrantLock configurationLock = new ReentrantLock();


    /**
     * Gets the logger for the supplied class.
     *
     * @param c
     *    the class for which a logger needs to be created.
     * @return
     *    the {@code LogAdapter} instance.
     */
    public static LogAdapter getLogger(Class<?> c) {
        checkConfig();
        if (snmp4jLogFactory == null) {
            return NoLogger.instance;
        }
        else {
            return snmp4jLogFactory.createLogger(c.getName());
        }
    }

    private static void checkConfig() {
        if (!configChecked) {
            configChecked = true;
            getFactoryFromSystemProperty();
        }
    }

    @SuppressWarnings("unchecked")
    private synchronized static void getFactoryFromSystemProperty() {
        try {
            String factory =
                    System.getProperty(SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, null);
            if (factory != null) {
                try {
                    Class<? extends LogFactory> c = (Class<? extends LogFactory>)Class.forName(factory);
                    snmp4jLogFactory = c.getDeclaredConstructor().newInstance();
                }
                catch (NoSuchMethodException | InstantiationException | IllegalAccessException |
                        ClassNotFoundException | InvocationTargetException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
        catch (SecurityException sec) {
            throw new RuntimeException(sec);
        }
    }

    /**
     * Returns the top level logger.
     * @return
     *    a LogAdapter instance.
     * @since 1.7
     */
    public LogAdapter getRootLogger() {
        return NoLogger.instance;
    }

    /**
     * Gets the logger for the supplied class name.
     *
     * @param className
     *    the class name for which a logger needs to be created.
     * @return
     *    the {@code LogAdapter} instance.
     * @since 1.7
     */
    public static LogAdapter getLogger(String className) {
        checkConfig();
        if (snmp4jLogFactory == null) {
            return NoLogger.instance;
        }
        else {
            return snmp4jLogFactory.createLogger(className);
        }
    }

    /**
     * Creates a Logger for the specified class. This method returns the
     * {@link NoLogger} logger instance which disables logging.
     * Overwrite this method the return a custom logger to enable logging for
     * SNMP4J.
     *
     * @param c
     *    the class for which a logger needs to be created.
     * @return
     *    the {@code LogAdapter} instance.
     */
    protected LogAdapter createLogger(Class<?> c) {
        return NoLogger.instance;
    }

    /**
     * Creates a Logger for the specified class. This method returns the
     * {@link NoLogger} logger instance which disables logging.
     * Overwrite this method the return a custom logger to enable logging for
     * SNMP4J.
     *
     * @param className
     *    the class name for which a logger needs to be created.
     * @return
     *    the {@code LogAdapter} instance.
     * @since 1.7
     */
    protected LogAdapter createLogger(String className) {
        return NoLogger.instance;
    }

    /**
     * Sets the log factory to be used by SNMP4J. Call this method before
     * any other SNMP4J class is referenced or created to set and use a custom
     * log factory.
     *
     * @param factory
     *    a {@code LogFactory} instance.
     */
    public static void setLogFactory(LogFactory factory) {
        configChecked = true;
        if (snmp4jLogFactory != null && snmp4jLogFactory.getRootLogger().isWarnEnabled()) {
            snmp4jLogFactory.getRootLogger().warn("LogFactory "+snmp4jLogFactory+" is being reset by "+factory);
        }
        snmp4jLogFactory = factory;
    }

    /**
     * Gets the log factory to be used by SNMP4J. If the log factory has not been
     * initialized by {@link #setLogFactory} a new instance of {@link LogFactory}
     * is returned.
     *
     * @return
     *    a {@code LogFactory} instance.
     * @since 1.7
     */
    public static LogFactory getLogFactory() {
        if (snmp4jLogFactory == null) {
            return new LogFactory();
        }
        return snmp4jLogFactory;
    }

    /**
     * Returns all available LogAdapters in depth first order.
     * @return
     *    a read-only Iterator.
     * @since 1.7
     */
    public Iterator<LogAdapter> loggers() {
        return Collections.singletonList((LogAdapter)NoLogger.instance).iterator();
    }

    /**
     * Close all handlers of a logger and set its level to {@code null} if it is not the root logger.
     * @param logger
     *    the logger to be reset.
     * @since 3.4.1
     */
    public void resetLogger(LogAdapter logger) {
    }

    public String getLoggerConfigPrefix() {
        return loggerConfigPrefix;
    }

    /**
     * Set the properties name prefix, including the trailing ".", used by {@link #updateConfiguration(Properties)} and
     * {@link #writeConfiguration(Properties)} for logger properties.
     * @param loggerConfigPrefix
     *    the prefix for {@link LogAdapter} configuration properties.
     * @since 3.4.1
     */
    public void setLoggerConfigPrefix(String loggerConfigPrefix) {
        this.loggerConfigPrefix = loggerConfigPrefix;
    }

    public String getLogHandlerConfigPrefix() {
        return logHandlerConfigPrefix;
    }

    /**
     * Set the properties name prefix, including the trailing ".", used by {@link #updateConfiguration(Properties)} and
     * {@link #writeConfiguration(Properties)} for log handler properties.
     * @param logHandlerConfigPrefix
     *    the prefix for log handler configuration properties.
     * @since 3.4.1
     */
    public void setLogHandlerConfigPrefix(String logHandlerConfigPrefix) {
        this.logHandlerConfigPrefix = logHandlerConfigPrefix;
    }

    /**
     * Reset the logging configuration. For all named log adapters, the reset operation removes and closes all handlers
     * (log factory specific) and (except for the root logger) sets the level to {@code null}.
     * The root logger's level is set to
     * {@link LogLevel#INFO}.
     * @since 3.4.1
     */
    public void reset() {
        configurationLock.lock();
        try {
            LogAdapter rootLogger = getRootLogger();
            for (Iterator<LogAdapter> it = loggers(); it.hasNext(); ) {
                LogAdapter logAdapter = it.next();
                logAdapter.setLogLevel(null);
            }
            rootLogger.setLogLevel(LogLevel.INFO);
        }
        finally {
            configurationLock.unlock();
        }
    }

    /**
     * Configure the log levels of the {@link LogAdapter} specified in the {@link java.util.Properties} provided by
     * the {@code propertiesReader} parameter. For example:
     * <pre>
     *     snmp4j.log.level.&lt;loggerName&gt;=&lt;LogLevel&gt;
     * </pre>
     *
     * @param config
     *      the {@link java.util.Properties} that contain properties with the prefixes {@link #getLoggerConfigPrefix()}
     *      and {@link #getLogHandlerConfigPrefix()}.
     */
    public void updateConfiguration(Properties config)  {
        Map<String, Map<String, String>> loggerConfig = new HashMap<>();
        Map<String, Map<String, String>> logHandlerConfig = new HashMap<>();
        String loggerConfigPrefix = getLoggerConfigPrefix();
        String logHandlerConfigPrefix = getLogHandlerConfigPrefix();
        for (Object key : config.keySet()) {
            if (key instanceof String) {
                if  (((String)key).startsWith(loggerConfigPrefix)) {
                    extractConfigProperty(config, loggerConfig, (String) key);
                }
                else if (((String)key).startsWith(logHandlerConfigPrefix)) {
                    extractConfigProperty(config, logHandlerConfig, (String)key);
                }
            }
        }
        configurationLock.lock();
        try {
            for (Iterator<LogAdapter> it = loggers(); it.hasNext(); ) {
                LogAdapter logAdapter = it.next();
                if (loggerConfig.containsKey(logAdapter.getName())) {
                    Map<String, String> newConfigAttributes =
                            loggerConfig.getOrDefault(logAdapter.getName(), Collections.emptyMap());
                    updateLogger(logAdapter, newConfigAttributes);
                    if (newConfigAttributes.containsKey(SNMP4J_LOG_HANDLER_LIST)) {
                        String handlerList = newConfigAttributes.get(SNMP4J_LOG_HANDLER_LIST);
                        String[] handlerNames = handlerList.split("(\\s|,)*");
                        for (String handlerName : handlerNames) {
                            addHandler(logAdapter, handlerName, logHandlerConfig.get(handlerName));
                        }
                    }
                    loggerConfig.remove(logAdapter.getName());
                }
                else {
                    resetLogger(logAdapter);
                }
            }
            for (Map.Entry<String, Map<String, String>> newLogger : loggerConfig.entrySet()) {
                LogAdapter logAdapter = createLogger(newLogger.getKey());
                logAdapter.setLogLevel(LogLevel.toLevel(newLogger.getValue().get(SNMP4J_LOG_LEVEL)));
            }
        }
        finally {
            configurationLock.unlock();
        }
    }

    private void extractConfigProperty(Properties newProperties, Map<String, Map<String, String>> config, String key) {
        try {
            int endOfPrefixPos = getLoggerConfigPrefix().length();
            String attribute = key.substring(endOfPrefixPos, key.indexOf('.', endOfPrefixPos));
            String id = key.substring(endOfPrefixPos+attribute.length()+1);
            Map<String, String> attributes = config.computeIfAbsent(id, k -> new TreeMap<>());
            attributes.put(attribute, newProperties.getProperty(key));
        }
        catch (RuntimeException rex) {
            // ignore
        }
    }

    protected void removeAllHandlers(LogAdapter logAdapter) {
    }

    protected void addHandler(LogAdapter logAdapter, String handlerName, Map<String, String> handlerConfig) {
    }

    protected void updateLogger(LogAdapter logAdapter, Map<String, String> loggerConfig) {
        logAdapter.setLogLevel(LogLevel.toLevel(loggerConfig.get(SNMP4J_LOG_LEVEL)));
    }

    public void writeConfiguration(Properties config) {
        configurationLock.lock();
        try {
            for (Iterator<LogAdapter> it = loggers(); it.hasNext(); ) {
                LogAdapter logAdapter = it.next();
                writeConfiguration(config, logAdapter);
            }
        }
        finally {
            configurationLock.unlock();
        }
    }

    protected void writeConfiguration(Properties config, LogAdapter logAdapter) {
        config.put(getLoggerConfigPrefix()+SNMP4J_LOG_LEVEL+"."+logAdapter.getName(), logAdapter.getLogLevel().toString());
        Iterator<?> handler = logAdapter.getLogHandler();
        StringBuilder stringBuilder = new StringBuilder();
        while (handler.hasNext()) {
            String handlerName = writeConfiguration(config, logAdapter, handler.next());
            stringBuilder.append(handlerName);
            if (handler.hasNext()) {
                stringBuilder.append(' ');
            }
        }
        if (stringBuilder.toString().trim().length() > 0) {
            config.put(getLoggerConfigPrefix()+logAdapter.getName()+"."+SNMP4J_LOG_HANDLER_LIST, stringBuilder.toString());
        }
        else {
            config.remove(getLoggerConfigPrefix()+logAdapter.getName()+"."+SNMP4J_LOG_HANDLER_LIST);
        }
    }

    protected String writeConfiguration(Properties config, LogAdapter logAdapter, Object handler) {
        return "";
    }
}
