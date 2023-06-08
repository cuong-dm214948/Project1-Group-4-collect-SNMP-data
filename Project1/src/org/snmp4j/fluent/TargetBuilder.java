/*_############################################################################
  _## 
  _##  SNMP4J - TargetBuilder.java  
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

import org.snmp4j.*;
import org.snmp4j.security.*;
import org.snmp4j.security.nonstandard.PrivAES192With3DESKeyExtension;
import org.snmp4j.security.nonstandard.PrivAES256With3DESKeyExtension;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.tls.TlsTmSecurityCallback;
import org.snmp4j.transport.tls.TlsX509CertifiedTarget;

import java.security.cert.X509Certificate;

/**
 * The {@code TargetBuilder} class creates SNMP {@link Target} instances using a fluent flow.
 * @param <A>
 *     the address type to generate a target for.
 * @author Frank Fock
 * @since 3.5.0
 */
public class TargetBuilder<A extends Address> {

    public enum SnmpVersion {
        v1(0),
        v2c(1),
        v3(3);

        private final int version;

        SnmpVersion(int version) {
            this.version = version;
        }
        public int getVersion() {
            return version;
        }
    };

    public enum AuthProtocol {
        md5("MD5", AuthMD5.ID),
        sha1("SHA-1", AuthSHA.ID),
        hmac128sha224("SHA-224", AuthHMAC128SHA224.ID),
        hmac192sha256("SHA-256", AuthHMAC192SHA256.ID),
        hmac256sha384("SHA-384", AuthHMAC256SHA384.ID),
        hmac384sha512("SHA-512", AuthHMAC384SHA512.ID);

        private final OID protocolID;
        private final String name;

        AuthProtocol(String name, OID protocolID) {
            this.name = name;
            this.protocolID = protocolID;
        }

        public OID getProtocolID() {
            return protocolID;
        }

        public String getName() {
            return name;
        }
    }

    public enum PrivProtocol {
        des("DES", PrivDES.ID),
        _3des("3DES", Priv3DES.ID),
        aes128("AES-128", PrivAES128.ID),
        aes192("AES-192", PrivAES192.ID),
        aes256("AES-256", PrivAES256.ID),
        aes192with3DESKeyExtension("AES-192-3DESkeyext", PrivAES192With3DESKeyExtension.ID),
        aes256with3DESKeyExtension("AES-256-3DESkeyext", PrivAES256With3DESKeyExtension.ID);

        private final OID protocolID;
        private final String name;

        PrivProtocol(String name, OID protocolID) {
            this.name = name;
            this.protocolID = protocolID;
        }

        public OID getProtocolID() {
            return protocolID;
        }

        public String getName() {
            return name;
        }

    }

    protected final SnmpBuilder snmpBuilder;
    protected A address;
    protected OctetString securityName;
    protected SnmpVersion snmpVersion = SnmpVersion.v3;
    protected Target<A> target;
    protected long timeoutMillis = SNMP4JSettings.getDefaultTimeoutMillis();
    protected int retries = SNMP4JSettings.getDefaultRetries();
    protected int maxSizeRequestPDU = SNMP4JSettings.getMaxSizeRequestPDU();

    /**
     * Creates a {@code TargetBuilder} from a given {@link SnmpBuilder} which is used to discover authoritative engine
     * ID and to get the security protocols to derive keys from passwords.
     * @param snmpBuilder
     *    a {@link SnmpBuilder} instance.
     */
    public TargetBuilder(SnmpBuilder snmpBuilder) {
        this.snmpBuilder = snmpBuilder;
    }

    protected TargetBuilder(SnmpBuilder snmpBuilder, A address) {
        this.snmpBuilder = snmpBuilder;
        this.address = address;
    }

    /**
     * Creates a {@code TargetBuilder} from a given {@link SnmpBuilder} which is used to discover authoritative engine
     * ID and to get the security protocols to derive keys from passwords. The given address specifies the target's
     * address.
     * @param snmpBuilder
     *    a {@link SnmpBuilder} instance.
     */
    public static <A extends Address> TargetBuilder<A> forAddress(SnmpBuilder snmpBuilder, A address) {
        return new TargetBuilder<A>(snmpBuilder, address);
    }

    /**
     * Sets the target's address.
     * @param address
     *    a transport {@link Address} instance.
     * @return
     *    this.
     */
    public TargetBuilder<A> address(A address) {
        this.address = address;
        return this;
    }

    public TargetBuilder<A> v1() {
        snmpVersion = SnmpVersion.v1;
        return this;
    }

    public TargetBuilder<A> v2c() {
        snmpVersion = SnmpVersion.v2c;
        return this;
    }

    public TargetBuilder<A> v3() {
        snmpVersion = SnmpVersion.v3;
        return this;
    }

    public TargetBuilder<A> timeout(long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
        return this;
    }

    public TargetBuilder<A> retries(int retries) {
        this.retries = retries;
        return this;
    }

    public void maxSizeRequestPDU(int maxSizeRequestPDU) {
        this.maxSizeRequestPDU = maxSizeRequestPDU;
    }

    public TargetBuilder<A> community(OctetString snmpV1V2Community) {
        securityName = snmpV1V2Community;
        if (snmpVersion == SnmpVersion.v3) {
            snmpVersion = SnmpVersion.v2c;
        }
        target = new CommunityTarget<>(address, securityName);
        return this;
    }

    public TargetBuilder<A>.DirectUserBuilder user(String securityName) {
        return user(securityName, null);
    }

    public TargetBuilder<A>.DirectUserBuilder user(String securityName, byte[] authoritativeEngineID) {
        return user(new OctetString(securityName), authoritativeEngineID);
    }

        public TargetBuilder<A>.DirectUserBuilder user(OctetString securityName) {
        return user(securityName, null);
    }

    /**
     * Creates a {@link DirectUserBuilder} based on this target builder for the specified security name authoritative
     * engine ID.
     * @param securityName
     *    the security name associated with the user.
     * @param authoritativeEngineID
     *    the authoritative engine ID of the target.
     * @return
     *    a {@link DirectUserBuilder} to build a {@link DirectUserTarget}.
     */
    public TargetBuilder<A>.DirectUserBuilder user(OctetString securityName, byte[] authoritativeEngineID) {
        snmpVersion = SnmpVersion.v3;
        return new DirectUserBuilder(securityName, authoritativeEngineID);
    }

    /**
     * Return a {@link TlsTargetBuilder} to specify special TLS target parameters.
     * @param identity
     *    the certificate identity.
     * @return
     *    a {@link TlsTargetBuilder} instance based on this {@link TargetBuilder}.
     */
    public TlsTargetBuilder tls(String identity) {
        return tls(new OctetString(identity));
    }

    /**
     * Return a {@link TlsTargetBuilder} to specify special TLS target parameters.
     * @param identity
     *    the certificate identity.
     * @return
     *    a {@link TlsTargetBuilder} instance based on this {@link TargetBuilder}.
     */
    public TlsTargetBuilder tls(OctetString identity) {
        return new TlsTargetBuilder(identity);
    }

    /**
     * Return a {@link TlsTargetBuilder} to specify special TLS target parameters.
     * @param identity
     *    the certificate identity.
     * @return
     *    a {@link TlsTargetBuilder} instance based on this {@link TargetBuilder}.
     */
    public TlsTargetBuilder dtls(String identity) {
        return dtls(new OctetString(identity));
    }

    /**
     * Return a {@link TlsTargetBuilder} to specify special TLS target parameters.
     * @param identity
     *    the certificate identity.
     * @return
     *    a {@link TlsTargetBuilder} instance based on this {@link TargetBuilder}.
     */
    public TlsTargetBuilder dtls(OctetString identity) {
        return new TlsTargetBuilder(identity);
    }

    /**
     * Build the target and return it.
     * @return
     *    a new {@link Target} instance.
     */
    public Target<A> build() {
        target.setTimeout(timeoutMillis);
        target.setRetries(retries);
        target.setVersion(snmpVersion.version);
        return target;
    }

    /**
     * Creates a {@link PduBuilder} based on this target builder.
     * @return
     *    a new {@link PduBuilder}.
     */
    public PduBuilder pdu() {
        return new PduBuilder(this);
    }

    public class DirectUserBuilder {
        private byte[] authoritativeEngineID;
        private final OctetString securityName;
        private AuthProtocol authenticationProtocol;
        private PrivProtocol privacyProtocol;
        private OctetString authPassword;
        private OctetString privPassword;

        protected DirectUserBuilder(OctetString securityName) {
            this.securityName = securityName;
        }

        protected DirectUserBuilder(OctetString securityName, byte[] authoritativeEngineID) {
            this.authoritativeEngineID = authoritativeEngineID;
            this.securityName = securityName;
        }

        public TargetBuilder<A>.DirectUserBuilder auth(AuthProtocol authenticationProtocol) {
            this.authenticationProtocol = authenticationProtocol;
            return this;
        }

        public TargetBuilder<A>.DirectUserBuilder priv(PrivProtocol privacyProtocol) {
            this.privacyProtocol = privacyProtocol;
            return this;
        }

        public TargetBuilder<A>.DirectUserBuilder authPassphrase(String authPassword) {
            return authPassphrase(OctetString.fromString(authPassword));
        }

        public TargetBuilder<A>.DirectUserBuilder authPassphrase(OctetString authPassword) {
            this.authPassword = authPassword;
            return this;
        }

        public TargetBuilder<A>.DirectUserBuilder privPassphrase(String privPassword) {
            return privPassphrase(OctetString.fromString(privPassword));
        }

        public TargetBuilder<A>.DirectUserBuilder privPassphrase(OctetString privPassword) {
            this.privPassword = privPassword;
            return this;
        }

        public TargetBuilder<A> done() {
            if (authoritativeEngineID == null) {
                authoritativeEngineID = snmpBuilder.snmp.discoverAuthoritativeEngineID(address, timeoutMillis);
            }
            byte[] authKey = null;
            byte[] privKey = null;
            SecurityProtocols securityProtocols = TargetBuilder.this.snmpBuilder.securityProtocols;
            if (authenticationProtocol != null && authPassword != null) {
                if (authoritativeEngineID == null) {
                    throw new IllegalArgumentException("Authoritative Engine ID not provided");
                }
                authKey = securityProtocols.
                        passwordToKey(authenticationProtocol.getProtocolID(), authPassword, authoritativeEngineID);
                if (privacyProtocol != null && privPassword != null) {
                    privKey = securityProtocols.
                            passwordToKey(privacyProtocol.getProtocolID(),
                                    authenticationProtocol.getProtocolID(), privPassword, authoritativeEngineID);
                }
            }
            if (authenticationProtocol == null || authKey == null) {
                target = new DirectUserTarget<A>(address, securityName, authoritativeEngineID,
                        null, null, null, null);
            }
            else if (privacyProtocol == null || privKey == null) {
                target = new DirectUserTarget<A>(address, securityName, authoritativeEngineID,
                        securityProtocols.getAuthenticationProtocol(authenticationProtocol.getProtocolID()),
                        new OctetString(authKey), null, null);
            }
            else {
                target = new DirectUserTarget<A>(address, securityName, authoritativeEngineID,
                        securityProtocols.getAuthenticationProtocol(authenticationProtocol.getProtocolID()),
                        new OctetString(authKey),
                        securityProtocols.getPrivacyProtocol(privacyProtocol.getProtocolID()),
                        new OctetString(privKey));
            }
            return TargetBuilder.this;
        }
    }

    public class TlsTargetBuilder {
        private final OctetString identity;
        private OctetString serverFingerprint;
        private OctetString clientFingerprint;
        private TlsTmSecurityCallback<X509Certificate> tlsTmSecurityCallback;

        protected TlsTargetBuilder(OctetString identity) {
            this.identity = identity;
        }

        public TlsTargetBuilder serverFingerprint(OctetString fingerprint) {
            this.serverFingerprint = fingerprint;
            return this;
        }

        public TlsTargetBuilder clientFingerprint(OctetString fingerprint) {
            this.clientFingerprint = fingerprint;
            return this;
        }

        public TlsTargetBuilder securityCallback(TlsTmSecurityCallback<X509Certificate> tlsTmSecurityCallback) {
            this.tlsTmSecurityCallback = tlsTmSecurityCallback;
            return this;
        }

        public TargetBuilder<A> done() {
            target = new TlsX509CertifiedTarget<>(
                    address, identity, serverFingerprint, clientFingerprint, tlsTmSecurityCallback);
            return TargetBuilder.this;
        }

    }
}
