/*_############################################################################
  _## 
  _##  SNMP4J - UserTarget.java  
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

package org.snmp4j;

import org.snmp4j.mp.MPv3;
import org.snmp4j.security.AuthenticationProtocol;
import org.snmp4j.security.PrivacyProtocol;
import org.snmp4j.security.USM;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
// for JavaDoc
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.Address;

import java.util.Objects;

/**
 * User based target for SNMPv3 or later.
 *
 *
 * @author Frank Fock
 * @version 3.1.0
 */
public class UserTarget<A extends Address> extends SecureTarget<A> {

    private static final long serialVersionUID = -1426511355567423746L;

    protected OctetString authoritativeEngineID = new OctetString();

    /**
     * Creates a target for a user based security model target.
     */
    public UserTarget() {
        setSecurityModel(MPv3.ID);
    }

    /**
     * Creates a target for a user based security model target that references security information (protocols and
     * keys) from a {@link USM}.
     * @param userTarget
     *         another {@link UserTarget} (or subclass thereof) to create a new instance from, by copying all data
     *         relevant for a {@link UserTarget}.
     * @since 3.4.0
     */
    public UserTarget(UserTarget<A> userTarget) {
        this(userTarget.getAddress(),
                userTarget.getSecurityName(), userTarget.getAuthoritativeEngineID(), userTarget.securityLevel);
        this.securityModel = userTarget.securityModel;
        this.setRetries(userTarget.getRetries());
        this.setTimeout(userTarget.getTimeout());
        this.setVersion(userTarget.getVersion());
        this.setMaxSizeRequestPDU(userTarget.getMaxSizeRequestPDU());
        this.setPreferredTransports(userTarget.getPreferredTransports());
    }

    /**
     * Creates a SNMPv3 USM target with security level noAuthNoPriv, one second time-out without retries.
     *
     * @param address
     *         the transport {@code Address} of the target.
     * @param securityName
     *         the USM security name to be used to access the target.
     * @param authoritativeEngineID
     *         the authoritative engine ID as a possibly zero length byte array which must not be {@code null}.
     */
    public UserTarget(A address, OctetString securityName, byte[] authoritativeEngineID) {
        super(address, securityName);
        setAuthoritativeEngineID(authoritativeEngineID);
        setSecurityModel(MPv3.ID);
    }

    /**
     * Creates a SNMPv3 USM target with the supplied security level, one second time-out without retries.
     *
     * @param address
     *         the transport {@code Address} of the target.
     * @param securityName
     *         the USM security name to be used to access the target.
     * @param authoritativeEngineID
     *         the authoritative engine ID as a possibly zero length byte array which must not be {@code null}.
     * @param securityLevel
     *         the {@link SecurityLevel} to use.
     *
     * @since 1.1
     */
    public UserTarget(A address, OctetString securityName, byte[] authoritativeEngineID, int securityLevel) {
        super(address, securityName);
        setAuthoritativeEngineID(authoritativeEngineID);
        setSecurityLevel(securityLevel);
        setSecurityModel(MPv3.ID);
    }

    /**
     * Sets the authoritative engine ID of this target.
     *
     * @param authoritativeEngineID
     *         a possibly zero length byte array (must not be {@code null}).
     */
    public void setAuthoritativeEngineID(byte[] authoritativeEngineID) {
        this.authoritativeEngineID.setValue(authoritativeEngineID);
    }

    /**
     * Gets the authoritative engine ID of this target.
     *
     * @return a possibly zero length byte array.
     */
    public byte[] getAuthoritativeEngineID() {
        return authoritativeEngineID.getValue();
    }

    @Override
    public String toString() {
        return "UserTarget[" + toStringAbstractTarget() +
                ", authoritativeEngineID=" + authoritativeEngineID +
                ", securityLevel=" + securityLevel +
                ']';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        UserTarget<?> that = (UserTarget) o;

        return Objects.equals(authoritativeEngineID, that.authoritativeEngineID);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (authoritativeEngineID != null ? authoritativeEngineID.hashCode() : 0);
        return result;
    }

    @Override
    public Target<A> duplicate() {
        UserTarget<A> copy =
                new UserTarget<A>(getAddress(), securityName, authoritativeEngineID.getValue(), securityLevel);
        copy.setRetries(getRetries());
        copy.setTimeout(getTimeout());
        copy.setMaxSizeRequestPDU(getMaxSizeRequestPDU());
        copy.setSecurityModel(getSecurityModel());
        copy.setVersion(getVersion());
        copy.setPreferredTransports(getPreferredTransports());
        return copy;
    }
}

