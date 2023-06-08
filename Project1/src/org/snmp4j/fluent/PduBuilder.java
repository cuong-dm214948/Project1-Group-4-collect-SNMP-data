/*_############################################################################
  _## 
  _##  SNMP4J - PduBuilder.java  
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
package org.snmp4j.fluent;

import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.util.DefaultPDUFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The {@code PduBuilder} creates SNMP {@link PDU}s based on a provided {@link TargetBuilder}.
 * @author Frank Fock
 * @since 3.5.0
 */
public class PduBuilder {

    protected final TargetBuilder<?> targetBuilder;
    protected OctetString contextEngineID;
    protected OctetString contextName;
    protected int pduType = PDU.GET;
    protected List<VariableBinding> vbs = new ArrayList<>();

    protected PduBuilder(TargetBuilder<?> targetBuilder) {
        this.targetBuilder = targetBuilder;
    }

    public PduBuilder contextName(String contextName) {
        return contextName(OctetString.fromString(contextName));
    }

    public PduBuilder contextName(OctetString contextName) {
        this.contextName = contextName;
        return this;
    }

    public PduBuilder contextEngineID(byte[] contextEngineID) {
        return contextEngineID(OctetString.fromByteArray(contextEngineID));
    }

    public PduBuilder contextEngineID(OctetString contextEngineID) {
        this.contextEngineID = contextEngineID;
        return this;
    }

    public PduBuilder type(int pduType) {
        this.pduType = pduType;
        return this;
    }

    public PduBuilder oid(OID... oids) {
        for (OID oid : oids) {
            vbs.add(new VariableBinding(oid));
        }
        return this;
    }

    public PduBuilder oids(String... oids) {
        for (String objectID : oids) {
            vbs.add(new VariableBinding(new OID(objectID)));
        }
        return this;
    }

    public PduBuilder vb(OID oid, Variable value) {
        vbs.add(new VariableBinding(oid, value));
        return this;
    }

    public PduBuilder vbs(VariableBinding... vbs) {
        Collections.addAll(this.vbs, vbs);
        return this;
    }

    /**
     * Build the actual {@link PDU} based on the previously provided parameters and return it.
     * @return
     *    a new {@link PDU} instance. For SNMP version greater or equal 3, a {@link ScopedPDU} is returned.
     */
    public PDU build() {
        PDU pdu = DefaultPDUFactory.createPDU(targetBuilder.snmpVersion.getVersion());
        if (pdu instanceof ScopedPDU) {
            ScopedPDU scopedPDU = (ScopedPDU)pdu;
            if (contextEngineID != null) {
                scopedPDU.setContextEngineID(contextEngineID);
            }
            scopedPDU.setContextName(contextName);
        }
        pdu.setType(pduType);
        pdu.setVariableBindings(vbs);
        return pdu;
    }

}
