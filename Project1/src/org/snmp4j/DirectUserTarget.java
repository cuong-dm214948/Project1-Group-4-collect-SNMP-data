/*_############################################################################
  _## 
  _##  SNMP4J - DirectUserTarget.java  
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
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;

import java.util.Objects;

// for JavaDoc

/**
 * User based target for SNMPv3 User Based Security Model {@link USM} or later that includes any necessary
 * authentication and privacy information, i.e. protocol references and localized keys.
 * In contrast to the base class {@link UserTarget}, the {@code DirectUserTarget} does not refer to user
 * information of a USM Local Configuration Storage except for caching engine times and boot counter for the
 * authoritative engine ID.
 *
 * @author Frank Fock
 * @since 3.4.0
 */
public class DirectUserTarget<A extends Address> extends UserTarget<A> {

    private static final long serialVersionUID = 2156539556559873408L;

    private AuthenticationProtocol authenticationProtocol;
    private PrivacyProtocol privacyProtocol;
    private OctetString authenticationKey;
    private OctetString privacyKey;

    /**
     * Creates a target for a user based security model target.
     */
    public DirectUserTarget() {
        setSecurityModel(MPv3.ID);
    }

    /**
     * Creates a target for a user based security model target without referencing security information from elsewhere.
     * @param userTarget
     *    the target based on an USM.
     */
    public DirectUserTarget(UserTarget<A> userTarget) {
        super(userTarget);
    }

    /**
     * Creates a SNMPv3 USM target with the supplied security level, one second time-out without retries.
     * The security level is deducted from the keys given ({@link #authenticationKey} and {@link #privacyKey}).
     * If both are {@code null} or have zero length, {@link SecurityLevel#noAuthNoPriv} is used;
     * if {@link #authenticationKey} is given but {@link #privacyKey} not, then {@link SecurityLevel#authNoPriv}, and
     * {@link SecurityLevel#authPriv} otherwise.
     *
     * @param address
     *         the transport {@code Address} of the target.
     * @param securityName
     *         the USM security name to be used to access the target.
     * @param authoritativeEngineID
     *         the authoritative engine ID as a possibly zero length byte array which must not be {@code null}.
     * @param authenticationProtocol
     *         the authentication protocol to be used (or {@code null} for {@link SecurityLevel#noAuthNoPriv}.
     * @param authenticationKey
     *         the localized authentication key (localized with the {@code authoritativeEngineID}) that will be used
     *         for this target instead of looking up the authentication key from the {@link USM}.
     * @param privacyProtocol
     *         the privacy protocol to be used (or {@code null} for {@link SecurityLevel#noAuthNoPriv} or
     *         {@link SecurityLevel#authNoPriv}.
     * @param privacyKey
     *         the localized privacy key (localized with the {@code authoritativeEngineID}) that will be used
     *         for this target instead of looking up the privacy key from the {@link USM}.
     *
     * @since 3.4.0
     */
    public DirectUserTarget(A address, OctetString securityName, byte[] authoritativeEngineID,
                            AuthenticationProtocol authenticationProtocol, OctetString authenticationKey,
                            PrivacyProtocol privacyProtocol, OctetString privacyKey) {
        super(address, securityName, authoritativeEngineID);
        setSecurityLevel((authenticationKey == null || authenticationKey.length() == 0) ? SecurityLevel.NOAUTH_NOPRIV :
                privacyKey == null || privacyKey.length() == 0 ? SecurityLevel.AUTH_NOPRIV : SecurityLevel.AUTH_PRIV);
        setSecurityModel(MPv3.ID);
        this.authenticationProtocol = authenticationProtocol;
        this.privacyProtocol = privacyProtocol;
        this.authenticationKey = authenticationKey;
        this.privacyKey = privacyKey;
    }

    /**
     * Gets the authentication key associated directly with this user target (without {@link USM} user table lookup).
     * If {@code null} is returned and the {@link #securityLevel} is not {@link SecurityLevel#noAuthNoPriv}, then the
     * authentication must be looked up from a {@link USM} instance, when sending a SNMPv3 message to a target,
     * @return
     *    the localized authentication key directly associated with this target.
     * @since 3.4.0
     */
    public OctetString getAuthenticationKey() {
        return authenticationKey;
    }

    /**
     * Sets the authentication key (localized for the {@link #authoritativeEngineID}) to be used for this target
     * directly.
     * Note: This has no effect unless {@link #securityLevel} is {@link SecurityLevel#authNoPriv} or
     * {@link SecurityLevel#authPriv}.
     * @param authenticationKey
     *         the localized authentication key (localized with the {@code authoritativeEngineID}) that will be used
     *         for this target instead of looking up the authentication key from the {@link USM} by the
     *         {@link #securityName}.
     * @since 3.4.0
     */
    public void setAuthenticationKey(OctetString authenticationKey) {
        this.authenticationKey = authenticationKey;
    }

    /**
     * Gets the privacy key associated directly with this user target (without {@link USM} user table lookup).
     * If {@code null} is returned and the {@link #securityLevel} is {@link SecurityLevel#authPriv} then the
     * privacy key must be looked up from a {@link USM} instance, when sending a SNMPv3 message to a target.
     * @return
     *    the localized privacy key directly associated with this target.
     * @since 3.4.0
     */
    public OctetString getPrivacyKey() {
        return privacyKey;
    }

    /**
     * Sets the privacy key (localized for the {@link #authoritativeEngineID}) to be used for this target directly.
     * Note: This has no effect unless {@link #authenticationKey} is also set and {@link #securityLevel} is
     * {@link SecurityLevel#authPriv}.
     * @param privacyKey
     *         the localized privacy key (localized with the {@code authoritativeEngineID}) that will be used
     *         for this target instead of looking up the privacy key from the {@link USM} by the {@link #securityName}.
     * @since 3.4.0
     */
    public void setPrivacyKey(OctetString privacyKey) {
        this.privacyKey = privacyKey;
    }

    /**
     * Get the {@link AuthenticationProtocol} associated with this target or {@code null} if there is no direct
     * user information provided but referenced by the {@link #securityName} from the {@link USM} or if there is no
     * authentication.
     * @return
     *        the (optional) authentication protocol associated with this target by direct reference
     *        (i.e not via {@link USM}).
     * @since 3.4.0
     */
    public AuthenticationProtocol getAuthenticationProtocol() {
        return authenticationProtocol;
    }

    /**
     * Set the {@link AuthenticationProtocol} associated with this target or {@code null} if there is no direct
     * user information provided but referenced by the {@link #securityName} from the {@link USM} or if there is no
     * authentication.
     * @param authenticationProtocol
     *        the (optional) authentication protocol associated with this target by direct reference
     *        (i.e not via {@link USM}).
     * @since 3.4.0
     */
    public void setAuthenticationProtocol(AuthenticationProtocol authenticationProtocol) {
        this.authenticationProtocol = authenticationProtocol;
    }

    /**
     * Get the {@link PrivacyProtocol} associated with this target or {@code null} if there is no direct
     * user information provided but referenced by the {@link #securityName} from the {@link USM} or there is no
     * privacy.
     * @return
     *        the (optional) privacy protocol associated with this target by direct reference
     *        (i.e not via {@link USM}).
     * @since 3.4.0
     */
    public PrivacyProtocol getPrivacyProtocol() {
        return privacyProtocol;
    }

    /**
     /**
     * Set the {@link PrivacyProtocol} associated with this target or {@code null} if there is no direct
     * user information provided but referenced by the {@link #securityName} from the {@link USM} or if there is no
     * privacy.
     * @param privacyProtocol
     *        the (optional) privacy protocol associated with this target by direct reference
     *        (i.e not via {@link USM}).
     * @since 3.4.0
     */
    public void setPrivacyProtocol(PrivacyProtocol privacyProtocol) {
        this.privacyProtocol = privacyProtocol;
    }

    @Override
    public String toString() {
        return "UserTarget[" + toStringAbstractTarget() +
                ", authoritativeEngineID=" + authoritativeEngineID +
                ", securityLevel=" + securityLevel +
                ", authenticationKey=" +
                    ((authenticationKey != null) ? "("+authenticationKey.length()+" bytes)" : "null") +
                ", privacyKey=" +
                ((privacyKey != null) ? "("+privacyKey.length()+" bytes)" : "null") +
                ']';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        DirectUserTarget<?> that = (DirectUserTarget<?>) o;

        if (getAuthenticationProtocol() != null ? !getAuthenticationProtocol().equals(that.getAuthenticationProtocol()) : that.getAuthenticationProtocol() != null)
            return false;
        if (getPrivacyProtocol() != null ? !getPrivacyProtocol().equals(that.getPrivacyProtocol()) : that.getPrivacyProtocol() != null)
            return false;
        if (getAuthenticationKey() != null ? !getAuthenticationKey().equals(that.getAuthenticationKey()) : that.getAuthenticationKey() != null)
            return false;
        return getPrivacyKey() != null ? getPrivacyKey().equals(that.getPrivacyKey()) : that.getPrivacyKey() == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (getAuthenticationProtocol() != null ? getAuthenticationProtocol().hashCode() : 0);
        result = 31 * result + (getPrivacyProtocol() != null ? getPrivacyProtocol().hashCode() : 0);
        result = 31 * result + (getAuthenticationKey() != null ? getAuthenticationKey().hashCode() : 0);
        result = 31 * result + (getPrivacyKey() != null ? getPrivacyKey().hashCode() : 0);
        return result;
    }

    @Override
    public Target<A> duplicate() {
        DirectUserTarget<A> copy =
                new DirectUserTarget<A>(getAddress(), securityName, authoritativeEngineID.getValue(),
                        authenticationProtocol, authenticationKey, privacyProtocol, privacyKey);
        copy.setSecurityLevel(getSecurityLevel());
        copy.setRetries(getRetries());
        copy.setTimeout(getTimeout());
        copy.setMaxSizeRequestPDU(getMaxSizeRequestPDU());
        copy.setSecurityModel(getSecurityModel());
        copy.setVersion(getVersion());
        copy.setPreferredTransports(getPreferredTransports());
        return copy;
    }
}

