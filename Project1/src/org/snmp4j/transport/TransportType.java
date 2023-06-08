/*_############################################################################
  _## 
  _##  SNMP4J - TransportType.java  
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

package org.snmp4j.transport;

/**
 * The {@code TransportType} defines the communication capabilities of a {@link org.snmp4j.TransportMapping}
 * regarding the communication initiation (thus its direction). SNMP application types Command Generator and
 * Notification Generators require the {@link #sender} type, whereas the Command Responder requires the
 * {@link #receiver} type. Type {@link #any} can be used by both application types.
 *
 * @author Frank Fock
 * @version 3.2.0
 */
public enum TransportType {

    /**
     * Can send messages to a remote entity.
     */
    sender,
    /**
     * Ca receive messages from a remote entity.
     */
    receiver,
    /**
     * Can send and receive messages to/from a remote entity.
     */
    any
}
