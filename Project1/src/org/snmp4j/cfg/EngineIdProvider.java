/*_############################################################################
  _## 
  _##  SNMP4J - EngineIdProvider.java  
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

package org.snmp4j.cfg;

import org.snmp4j.smi.OctetString;

/**
 * An {@code EngineIdProvider} holds persistently the engine ID of a SNMP engine.
 *
 * @author Frank Fock
 * @version 3.5
 * @since 3.5
 */
public interface EngineIdProvider {

    /**
     * Gets the engine ID for the SNMP entity associated with this {@link EngineIdProvider}.
     * @param defaultEngineID
     *    the engine ID for this entity, if there is no persistently saved engine ID yet.
     * @return
     *    the persistently saved engine ID or the reference to the {@code defaultEngineID} which is then
     *    persistently stored.
     */
    OctetString getEngineId(OctetString defaultEngineID);

    /**
     * Sets the persistently stored engine ID to a new value.
     * @param engineId
     *    the new engine ID for this SNMP entity.
     */
    void resetEngineId(OctetString engineId);
}
