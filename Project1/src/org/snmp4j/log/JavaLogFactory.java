/*_############################################################################
  _## 
  _##  SNMP4J - JavaLogFactory.java  
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

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.*;

/**
 * The {@code JavaLogFactory} implements a SNMP4J LogFactory for
 * Java logging. In order to use Java's {@code java.util.logging}
 * for logging SNMP4J log messages the static {@link LogFactory#setLogFactory}
 * method has to be used before any SNMP4J class is referenced or instantiated.
 *
 * @author Frank Fock
 * @version 3.4.1
 */
public class JavaLogFactory extends LogFactory {

    public static final String JAVA_CONSOLE_HANDLER = "java.util.logging.ConsoleHandler";
    public static final String JAVA_FILE_HANDLER = "java.util.logging.FileHandler";
    public static final String FH_ATTR_PATTERN = "pattern";
    public static final String DEFAULT_PATTERN = "%h/java%u.log";
    public static final String FH_ATTR_COUNT = "count";
    public static final String DEFAULT_COUNT = "1";
    public static final String FH_ATTR_APPEND = "append";
    public static final String FH_ATTR_LIMIT = "limit";
    public static final String DEFAULT_LIMIT = "0";
    public static final String FH_ATTR_FORMATTER = "formatter";
    public static final String SF_ATTR_FORMAT = "format";


    public JavaLogFactory() {
    }

    public JavaLogFactory(boolean removeExistingHandlers) {
        if (removeExistingHandlers) {
            for (Handler handler : Logger.getLogger("").getHandlers()) {
                Logger.getLogger("").removeHandler(handler);
            }
        }
    }

    protected LogAdapter createLogger(Class<?> c) {
        return new JavaLogAdapter(Logger.getLogger(c.getName()));
    }

    protected LogAdapter createLogger(String className) {
        return new JavaLogAdapter(Logger.getLogger(className));
    }

    public LogAdapter getRootLogger() {
        return new JavaLogAdapter(Logger.getLogger(""));
    }

    public Iterator<LogAdapter> loggers() {
        Enumeration<String> loggerNames = LogManager.getLogManager().getLoggerNames();
        return new JavaLogAdapterIterator(loggerNames);
    }

    public class JavaLogAdapterIterator implements Iterator<LogAdapter> {
        private Enumeration<String> loggerNames;

        protected JavaLogAdapterIterator(Enumeration<String> loggerNames) {
            this.loggerNames = loggerNames;
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }

        public final boolean hasNext() {
            return loggerNames.hasMoreElements();
        }

        public LogAdapter next() {
            String loggerName = loggerNames.nextElement();
            Logger logger = Logger.getLogger(loggerName);
            return new JavaLogAdapter(logger);
        }
    }

    @Override
    protected void addHandler(LogAdapter logAdapter, String handlerName, Map<String, String> handlerConfig) {
        Handler handler = null;
        switch (handlerName) {
            case JAVA_CONSOLE_HANDLER:
                handler = new ConsoleHandler();
                break;
            case JAVA_FILE_HANDLER:
                try {
                    FileHandler fileHandler = new FileHandler(handlerConfig.getOrDefault(FH_ATTR_PATTERN, DEFAULT_PATTERN),
                            Long.parseLong(handlerConfig.getOrDefault(FH_ATTR_LIMIT, DEFAULT_LIMIT)),
                            Integer.parseInt(handlerConfig.getOrDefault(FH_ATTR_COUNT, DEFAULT_COUNT)),
                            Boolean.parseBoolean(handlerConfig.getOrDefault(FH_ATTR_APPEND, "false")));
                    String formatterClass = handlerConfig.get(FH_ATTR_FORMATTER);
                    if (formatterClass != null) {
                        if (formatterClass.equals(SimpleFormatter.class.getName())) {
                            String simpleFormat = handlerConfig.get(SF_ATTR_FORMAT);
                            if (simpleFormat != null) {
                                System.setProperty(SimpleFormatter.class.getName()+"."+SF_ATTR_FORMAT, simpleFormat);
                            }
                        }
                        Formatter formatter = (Formatter) Class.forName(formatterClass).
                                getConstructor((Class<?>) null).newInstance((Object) null);
                        fileHandler.setFormatter(formatter);
                    }
                    handler = fileHandler;
                } catch (IOException | ClassNotFoundException | NoSuchMethodException | InstantiationException |
                        IllegalAccessException | InvocationTargetException e) {
                    e.printStackTrace();
                }
                break;
        }
        if (handler != null) {
            String handlerLevel = handlerConfig.get(SNMP4J_LOG_LEVEL);
            if (handlerLevel != null) {
                Level level = JavaLogAdapter.fromSnmp4jToJdk(LogLevel.toLevel(handlerLevel));
                if (level != null) {
                    handler.setLevel(level);
                }
            }
            ((JavaLogAdapter) logAdapter).getJavaLogger().addHandler(handler);
        }
    }

    @Override
    protected void removeAllHandlers(LogAdapter logAdapter) {
        Logger logger = ((JavaLogAdapter)logAdapter).getJavaLogger();
        Handler[] handlers = logger.getHandlers();
        for (Handler handler : handlers) {
            logger.removeHandler(handler);
        }
    }
}
