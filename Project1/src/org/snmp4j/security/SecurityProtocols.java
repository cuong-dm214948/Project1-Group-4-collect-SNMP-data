/*_############################################################################
  _## 
  _##  SNMP4J - SecurityProtocols.java  
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

import org.snmp4j.SNMP4JSettings;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.security.nonstandard.NonStandardSecurityProtocol;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.util.PDUFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.*;

/**
 * The {@code SecurityProtocols} class holds all authentication and privacy protocols for a SNMP entity.
 * <p>
 * To register security protocols other than the default, set the system property {@link #SECURITY_PROTOCOLS_PROPERTIES}
 * to a customized version of the {@code SecurityProtocols.properties} file. The path has to be specified
 * relatively to this class.
 *
 * @author Frank Fock
 * @author Jochen Katz
 * @version 3.5.0
 */
public class SecurityProtocols implements Serializable {

    private static final long serialVersionUID = 3800474900139635836L;

    public enum SecurityProtocolType {
        authentication,
        privacy
    }

    public enum SecurityProtocolSet {
        /**
         * No security protocol at all, this will effectively disable any SNMPv3 communication.
         */
        none,
        /**
         * Activate only the most secure protocol or equally secure variants thereof (e.g SHA512 and AES256)
         */
        maxSecurity,
        /**
         * Activate all authentication and privacy protocols that are considered safe at the time of the
         * SNMP4J release. Currently MD5 and SHA-1 are no longer considered to be safe.
         */
        defaultSecurity,
        /**
         * Activate any available protocol not deprecated yet.
         */
        maxCompatibility
    };

    private final Hashtable<OID, AuthenticationProtocol> authProtocols;
    private final Hashtable<OID, PrivacyProtocol> privProtocols;

    public static final String SECURITY_PROTOCOLS_PROPERTIES =
            "org.snmp4j.securityProtocols";
    private static final String SECURITY_PROTOCOLS_PROPERTIES_DEFAULT =
            "SecurityProtocols.properties";
    private static final LogAdapter logger = LogFactory.getLogger(SecurityProtocols.class);

    private static SecurityProtocols instance = null;
    private int maxAuthDigestLength = 0;
    private int maxPrivDecryptParamsLength = 0;

    protected SecurityProtocols() {
        authProtocols = new Hashtable<OID, AuthenticationProtocol>(5);
        privProtocols = new Hashtable<OID, PrivacyProtocol>(5);
    }

    /**
     * Create a new {@link SecurityProtocols} collection to be used in
     * {@link org.snmp4j.mp.MPv3#MPv3(byte[], PDUFactory, SecurityProtocols, SecurityModels, CounterSupport)}
     * constructor. Using this constructor creates a non-default instance of a security protocols collections.
     * You can set it as default instance by calling {@link #setSecurityProtocols(SecurityProtocols)} with this
     * instance later to set it as default.
     * @param initialSecurityProtocolSet
     *    defines the initial set of
     */
    public SecurityProtocols(SecurityProtocolSet initialSecurityProtocolSet) {
        this();
        addPredefinedProtocolSet(initialSecurityProtocolSet);
    }

    /**
     * Remove all security protocols from this set.
     * @since 3.5.0
     */
    public void removeAll() {
        this.authProtocols.clear();
        this.privProtocols.clear();
    }

    /**
     * Add a consistent, predefined, set of security protocols to this security protocol set.
     * @param initialSecurityProtocolSet
     *    the set that defines the protocols to add.
     * @since 3.5.0
     */
    public void addPredefinedProtocolSet(SecurityProtocolSet initialSecurityProtocolSet) {
        switch(initialSecurityProtocolSet) {
            case maxCompatibility: {
                addAuthenticationProtocol(new AuthMD5());
                addAuthenticationProtocol(new AuthSHA());
                // fall through
            }
            case defaultSecurity: {
                addAuthenticationProtocol(new AuthHMAC128SHA224());
                addAuthenticationProtocol(new AuthHMAC192SHA256());
                addAuthenticationProtocol(new AuthHMAC256SHA384());
                addPrivacyProtocol(new PrivDES());
                addPrivacyProtocol(new PrivAES128());
                addPrivacyProtocol(new PrivAES192());
                // fall through
            }
            case maxSecurity: {
                addAuthenticationProtocol(new AuthHMAC384SHA512());
                addPrivacyProtocol(new PrivAES256());
                break;
            }
        }
    }

    /**
     * Get an instance of class SecurityProtocols.
     *
     * @return the globally used SecurityProtocols object.
     */
    public static SecurityProtocols getInstance() {
        if (instance == null) {
            instance = new SecurityProtocols();
        }
        return instance;
    }

    /**
     * Set the {@code SecurityProtocols}
     *
     * @param securityProtocols
     *         SecurityProtocols
     */
    public static void setSecurityProtocols(SecurityProtocols securityProtocols) {
        SecurityProtocols.instance = securityProtocols;
    }

    /**
     * Get the security protocol ({@link AuthenticationProtocol} or {@link PrivacyProtocol}) for the specified protocol
     * OID.
     *
     * @param protocolID
     *         an object identifier of the security protocol to return.
     *
     * @return the security protocol or {@code null} if a protocol with such an ID has not been added yet.
     * @since 2.6.0
     */
    public SecurityProtocol getSecurityProtocol(OID protocolID) {
        SecurityProtocol protocol = getAuthenticationProtocol(protocolID);
        if (protocol == null) {
            protocol = getPrivacyProtocol(protocolID);
        }
        return protocol;
    }

    /**
     * Add the default SecurityProtocols.
     * <p>
     * The names of the SecurityProtocols to add are read from a properties file.
     *
     * @return this SecurityProtocols instance for chaining configuration.
     * @throws InternalError
     *         if {@link SNMP4JSettings#isExtensibilityEnabled()} is {@code true} and corresponding properties file with
     *         the security protocols configuration cannot be opened/read.
     */
    @SuppressWarnings("unchecked")
    public synchronized SecurityProtocols addDefaultProtocols() {
        if (SNMP4JSettings.isExtensibilityEnabled()) {
            String secProtocols =
                    System.getProperty(SECURITY_PROTOCOLS_PROPERTIES, SECURITY_PROTOCOLS_PROPERTIES_DEFAULT);
            InputStream is = SecurityProtocols.class.getResourceAsStream(secProtocols);
            if (is == null) {
                throw new InternalError("Could not read '" + secProtocols + "' from classpath!");
            }
            Properties props = new Properties();
            try {
                props.load(is);
                for (Iterator<String> en = props.stringPropertyNames().iterator(); en.hasNext(); ) {
                    String className = en.next();
                    String customOidString = props.getProperty(className);
                    OID customOID = null;
                    if (customOidString != null) {
                        customOID = new OID(customOidString);
                    }
                    try {
                        Class<? extends SecurityProtocol> c = (Class<? extends SecurityProtocol>) Class.forName(className);
                        Object proto = c.getDeclaredConstructor().newInstance();
                        if ((proto instanceof NonStandardSecurityProtocol) && (customOID != null) && (customOID.size() > 0)) {
                            if (logger.isInfoEnabled()) {
                                logger.info("Assigning custom ID '" + customOID + "' to security protocol " + className);
                            }
                            ((NonStandardSecurityProtocol) proto).setID(customOID);
                        }
                        if (proto instanceof AuthenticationProtocol) {
                            addAuthenticationProtocol((AuthenticationProtocol) proto);
                        } else if (proto instanceof PrivacyProtocol) {
                            addPrivacyProtocol((PrivacyProtocol) proto);
                        } else {
                            logger.error(
                                    "Failed to register security protocol because it does " +
                                            "not implement required interfaces: " + className);
                        }
                    } catch (Exception cnfe) {
                        logger.error(cnfe);
                        throw new InternalError(cnfe.toString());
                    }
                }
            } catch (IOException iox) {
                String txt = "Could not read '" + secProtocols + "': " +
                        iox.getMessage();
                logger.error(txt);
                throw new InternalError(txt);
            } finally {
                try {
                    is.close();
                } catch (IOException ex) {
                    // ignore
                    logger.warn(ex);
                }
            }
        } else {
// Unsecure:      addAuthenticationProtocol(new AuthMD5());
// Unsecure:      addAuthenticationProtocol(new AuthSHA());
            addAuthenticationProtocol(new AuthHMAC128SHA224());
            addAuthenticationProtocol(new AuthHMAC192SHA256());
            addAuthenticationProtocol(new AuthHMAC256SHA384());
            addAuthenticationProtocol(new AuthHMAC384SHA512());
            addPrivacyProtocol(new PrivDES());
            addPrivacyProtocol(new PrivAES128());
            addPrivacyProtocol(new PrivAES192());
            addPrivacyProtocol(new PrivAES256());
        }
        return this;
    }

    /**
     * Add the given {@link AuthenticationProtocol}. If an authentication protocol with the supplied ID already exists,
     * the supplied authentication protocol will not be added and the security protocols will not be unchang.
     *
     * @param auth
     *         the AuthenticationProtocol to add (an existing authentication protcol with {@code auth}'s ID remains
     *         unchanged).
     */
    public synchronized void addAuthenticationProtocol(AuthenticationProtocol auth) {
        if (authProtocols.get(auth.getID()) == null) {
            authProtocols.put(auth.getID(), auth);
            if (auth.getDigestLength() > maxAuthDigestLength) {
                maxAuthDigestLength = auth.getDigestLength();
            }
        }
    }

    /**
     * Get the {@link AuthenticationProtocol} with the given ID.
     *
     * @param id
     *         The unique ID (specified as {@link OID}) of the AuthenticationProtocol.
     *
     * @return the AuthenticationProtocol object if it was added before, or null if not.
     */
    public AuthenticationProtocol getAuthenticationProtocol(OID id) {
        if (id == null) {
            return null;
        }
        return authProtocols.get(id);
    }

    /**
     * Remove the given {@link AuthenticationProtocol}.
     *
     * @param authOID
     *         The object identifier of the protocol to remove
     */
    public void removeAuthenticationProtocol(OID authOID) {
        authProtocols.remove(authOID);
    }

    /**
     * Add the given {@link PrivacyProtocol}. If a privacy protocol with the supplied ID already exists, the supplied
     * privacy protocol will not be added and the security protocols will not be changed.
     *
     * @param priv
     *         the PrivacyProtocol to add (an existing privacy protocol with {@code priv}'s ID remains unchanged).
     */
    public synchronized void addPrivacyProtocol(PrivacyProtocol priv) {
        if (privProtocols.get(priv.getID()) == null) {
            privProtocols.put(priv.getID(), priv);
            if (priv.getDecryptParamsLength() > maxPrivDecryptParamsLength) {
                maxPrivDecryptParamsLength = priv.getDecryptParamsLength();
            }
        }
    }

    /**
     * Get the PrivacyProtocol with the given ID.
     *
     * @param id
     *         The unique ID (specified as {@link OID}) of the PrivacyProtocol.
     *
     * @return the {@link PrivacyProtocol} object if it was added before, or null if not.
     */
    public PrivacyProtocol getPrivacyProtocol(OID id) {
        if (id == null) {
            return null;
        }
        return privProtocols.get(id);
    }

    /**
     * Remove the given {@link PrivacyProtocol}.
     *
     * @param privOID
     *         The object identifier of the protocol to remove
     */
    public void removePrivacyProtocol(OID privOID) {
        privProtocols.remove(privOID);
    }


    /**
     * Generates the localized key for the given password and engine id for the authentication protocol specified by the
     * supplied OID.
     *
     * @param authProtocolID
     *         an {@code OID} identifying the authentication protocol to use.
     * @param passwordString
     *         the authentication pass phrase.
     * @param engineID
     *         the engine ID of the authoritative engine.
     *
     * @return the localized authentication key.
     */
    public byte[] passwordToKey(OID authProtocolID,
                                OctetString passwordString,
                                byte[] engineID) {

        AuthenticationProtocol protocol = authProtocols.get(authProtocolID);
        if (protocol == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Cannot convert password to key because authentication protocol '"+authProtocolID+
                        "' not found in authProtocols="+authProtocols);
            }
            return null;
        }
        return protocol.passwordToKey(passwordString, engineID);
    }

    /**
     * Generates the localized key for the given password and engine id for the privacy protocol specified by the
     * supplied OID.
     *
     * @param privProtocolID
     *         an {@code OID} identifying the privacy protocol the key should be created for.
     * @param authProtocolID
     *         an {@code OID} identifying the authentication protocol to use.
     * @param passwordString
     *         the authentication pass phrase.
     * @param engineID
     *         the engine ID of the authoritative engine.
     *
     * @return the localized privacy key.
     */
    public byte[] passwordToKey(OID privProtocolID,
                                OID authProtocolID,
                                OctetString passwordString,
                                byte[] engineID) {

        AuthenticationProtocol authProtocol = authProtocols.get(authProtocolID);
        if (authProtocol == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Cannot convert password to key because authentication protocol '"+authProtocolID+
                        "' not found in authProtocols="+authProtocols);
            }
            return null;
        }
        PrivacyProtocol privProtocol = privProtocols.get(privProtocolID);
        if (privProtocol == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Cannot convert password to key because privacy protocol '"+privProtocolID+
                        "' not found in privacyProtocols="+privProtocols);
            }
            return null;
        }
        byte[] key = authProtocol.passwordToKey(passwordString, engineID);

        if (key == null) {
            return null;
        }
        if (key.length >= privProtocol.getMinKeyLength()) {
            if (key.length > privProtocol.getMaxKeyLength()) {
                // truncate key
                byte[] truncatedKey = new byte[privProtocol.getMaxKeyLength()];
                System.arraycopy(key, 0, truncatedKey, 0, privProtocol.getMaxKeyLength());
                return truncatedKey;
            }
            return key;
        }
        // extend key if necessary
        return privProtocol.extendShortKey(key, passwordString, engineID, authProtocol);
    }

    /**
     * Gets the maximum authentication key length of the all known authentication protocols.
     *
     * @return the maximum authentication key length of all authentication protocols that have been added to this
     * {@code SecurityProtocols} instance.
     */
    public int getMaxAuthDigestLength() {
        return maxAuthDigestLength;
    }

    /**
     * Gets the maximum privacy key length of the currently known privacy protocols.
     *
     * @return the maximum privacy key length of all privacy protocols that have been added to this
     * {@code SecurityProtocols} instance.
     */
    public int getMaxPrivDecryptParamsLength() {
        return maxPrivDecryptParamsLength;
    }

    /**
     * Limits the supplied key value to the specified maximum length
     *
     * @param key
     *         the key to truncate.
     * @param maxKeyLength
     *         the maximum length of the returned key.
     *
     * @return the truncated key with a length of
     * {@code min(key.length, maxKeyLength)}.
     * @since 1.9
     */
    public byte[] truncateKey(byte[] key, int maxKeyLength) {
        byte[] truncatedNewKey = new byte[Math.min(maxKeyLength, key.length)];
        System.arraycopy(key, 0, truncatedNewKey, 0, truncatedNewKey.length);
        return truncatedNewKey;
    }

    /**
     * Returns the object identifiers ({@link OID}s) of the {@link SecurityProtocol}s known to this
     * {@link SecurityProtocols} instance that have the specified type.
     * @param securityProtocolType
     *    the security protocol type (authentication or privacy).
     * @return
     *    a collection of security protocol identifiers of the specified type or {@code null} if the type is not
     *    supported by this instance.
     * @since 3.3.4
     */
    public Collection<OID> getSecurityProtocolOIDs(SecurityProtocolType securityProtocolType) {
        switch (securityProtocolType) {
            case authentication: return authProtocols.keySet();
            case privacy: return privProtocols.keySet();
        }
        return null;
    }
}

