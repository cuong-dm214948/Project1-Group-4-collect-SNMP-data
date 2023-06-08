/*_############################################################################
  _## 
  _##  SNMP4J - SecretOctetString.java  
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
import org.snmp4j.smi.OctetString;

/**
 * The {@link SecretOctetString} is an {@link OctetString} for secret data like keys and passwords.
 * It behaves like a regular {@link org.snmp4j.smi.OctetString} except that the {@link #toString()} method
 * does not reveal any security information but returns a {@link AuthHMAC192SHA256} hash of the real
 * security information.
 * @author Frank Fock
 * @version 3.6.1
 * @since 3.6.1
 */
public class SecretOctetString extends OctetString {
    private static final long serialVersionUID = -9186248947167181339L;
    private static final AuthHMAC192SHA256 digester = new AuthHMAC192SHA256();

    public SecretOctetString(OctetString secret) {
        super(secret);
    }

    public SecretOctetString(byte[] rawValue) {
        super(rawValue);
    }

    /**
     * Creates an octet string from an byte array.
     * @param rawValue
     *    an array of bytes.
     * @param offset
     *    the position (zero based) of the first byte to be copied from
     *    {@code rawValue}into the new {@code OctetString}.
     * @param length
     *    the number of bytes to be copied.
     */
    public SecretOctetString(byte[] rawValue, int offset, int length) {
        super(rawValue, offset, length);
    }

    public SecretOctetString() {
        super();
    }

    /**
     * Create a {@link SecretOctetString} from a {@link OctetString} but return {@code null} if the given
     * {@link OctetString} is {@code null}.
     * @param octetString
     *    an {@link OctetString} whose {@code to*String} methods needs to be protected against disclosing sensitive
     *    information.
     * @return
     *    the new {@link SecretOctetString} or {@code null}.
     */
    public static SecretOctetString fromOctetString(OctetString octetString) {
        if (octetString == null) {
            return null;
        }
        return new SecretOctetString(octetString);
    }

    @Override
    public String toString() {
        if (SNMP4JSettings.isSecretLoggingEnabled()) {
            return super.toString();
        }
        return getDigest();
    }

    private String getDigest() {
        try {
            byte[] hash = digester.hash(getValue());
            return "{secretSHA256="+new OctetString(hash).toHexString()+"}";
        }
        catch (InternalError ie) {
            return "{secretSHA256=?>";
        }
    }

    @Override
    public String toHexString() {
        if (SNMP4JSettings.isSecretLoggingEnabled()) {
            return super.toHexString();
        }
        return getDigest();
    }

    @Override
    public String toHexString(char separator) {
        if (SNMP4JSettings.isSecretLoggingEnabled()) {
            return super.toHexString(separator);
        }
        return getDigest();
    }

    @Override
    public String toString(char separator, int radix) {
        if (SNMP4JSettings.isSecretLoggingEnabled()) {
            return super.toString(separator, radix);
        }
        return getDigest();
    }

    @Override
    public String toString(int radix) {
        if (SNMP4JSettings.isSecretLoggingEnabled()) {
            return super.toString(radix);
        }
        return getDigest();
    }
}
