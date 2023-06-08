/*_############################################################################
  _## 
  _##  SNMP4J - SSLEngineConfigurator.java  
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

package org.snmp4j.transport.tls;

import org.snmp4j.TransportStateReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.GeneralSecurityException;

/**
 * The {@link SSLEngineConfigurator} interface is implemented by users of the {@link org.snmp4j.transport.TLSTM} or
 * {@link org.snmp4j.transport.DTLSTM} transport protocols to configure new TLS (SSL) connections.
 */
public interface SSLEngineConfigurator {
    /**
     * Configure the supplied SSLEngine for TLS.
     * Configuration includes enabled protocol(s),
     * cipher codes, etc.
     *
     * @param sslEngine a {@link SSLEngine} to configure.
     */
    void configure(SSLEngine sslEngine);

    /**
     * Gets the SSLContext for this SSL connection.
     *
     * @param useClientMode           {@code true} if the connection is established in client mode.
     * @param transportStateReference the transportStateReference with additional
     *                                security information for the SSL connection
     *                                to establish.
     * @return the SSLContext.
     * @throws GeneralSecurityException if the TLS context initialization failed because of configuration errors.
     */
    SSLContext getSSLContext(boolean useClientMode, TransportStateReference transportStateReference)
            throws GeneralSecurityException;
}
