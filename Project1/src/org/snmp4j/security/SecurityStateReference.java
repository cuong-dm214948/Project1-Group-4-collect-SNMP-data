/*_############################################################################
  _## 
  _##  SNMP4J - SecurityStateReference.java  
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
package org.snmp4j.security;

import org.snmp4j.Target;

/**
 * The {@code SecurityStateReference} interface is an empty marker
 * interface for security model dependent state references.
 *
 * @author Frank Fock
 * @version 3.4.0
 */
public interface SecurityStateReference {

    /**
     * After a {@link SecurityStateReference} has been created for on outgoing message, this method might be called
     * by the {@link org.snmp4j.mp.MPv3} to apply security information contained in the target object to the security
     * state information. By default, this method does nothing and defers the security state information initialization
     * the the corresponding {@link SecurityModel} and returns {@code false}.
     * @param target
     *    a {@link Target} subclass instance with security information.
     * @return
     *    {@code true} if the security information of the supplied target could be applied and {@code false} otherwise.
     */
    default boolean applyTargetSecurityInformation(Target<?> target) {
        return false;
    }

    /**
     * Sets the {@code isCachedForResponseProcessing} flag to indicate whether this security state reference has been
     * cached for response processing which means it will be used later for response or report processing rather than
     * for requests or notifications (traps).
     *
     * @param isCachedForResponseProcessing
     *    if {@code true}, this security state reference has been cached for response processing.
     * @since 3.4.0
     */
    void setCachedForResponseProcessing(boolean isCachedForResponseProcessing);

    /**
     * Returns the {@code isCachedForResponseProcessing} flag indicating whether this security state reference has been
     * cached for response processing which means it can be used later for response or report processing rather than
     * for requests or notifications (traps).
     * @return
     *    if {@code true}, this security state reference has been cached for response processing.
     */
    boolean isCachedForResponseProcessing();
}

