/*_############################################################################
  _## 
  _##  SNMP4J - X509TlsTransportMappingConfig.java  
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

import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;

/**
 * The {@code TlsTransportMappingConfig} interface provides means to plug in a {@link TlsTmSecurityCallback} into
 * a {@link org.snmp4j.TransportMapping} that uses {@link X509Certificate}s for TLS.
 *
 * @author Frank Fock
 * @since 3.6
 */

public interface X509TlsTransportMappingConfig extends TlsTransportMappingConfig<X509Certificate> {

    /**
     * Gets the (optional and possibly {@code null}) revocation checker for the cert path validation of X509
     * certificates.
     * @return
     *    {@code null} to disable cert path validation with CLR checking or a properly configured cert path checker
     *    instance.
     * @since 3.6
     */
    PKIXRevocationChecker getPKIXRevocationChecker();

    /**
     * Sets the (optional and possibly {@code null}) revocation checker for the cert path validation of X509
     * certificates.
     * @param pkixRevocationChecker
     *    {@code null} to disable cert path validation with CLR checking or a properly configured cert path checker
     *    instance.
     * @since 3.6
     */
    void setPKIXRevocationChecker(PKIXRevocationChecker pkixRevocationChecker);

    /**
     * Gets the X509 certificate revocation list (CRL) URI, if defined.
     * @return
     *    {@code null} if there is no CRL available/necessary or a URI string that points to a CRL file.
     * @since 3.6.0
     */
    String getX509CertificateRevocationListURI();

    /**
     * Sets the X509 certificate revocation list (CRL) URI, to enable CRL checking.
     * @param crlURI
     *    {@code null} if there is no CRL available/necessary or a URI string that points to a CRL file.
     * @since 3.6.0
     */
    void setX09CertificateRevocationListURI(String crlURI);
}
