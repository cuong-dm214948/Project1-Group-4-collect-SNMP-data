/*_############################################################################
  _## 
  _##  SNMP4J - DictionaryOIDTextFormat.java  
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

package org.snmp4j.util;

import org.snmp4j.smi.OID;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * The {@link DictionaryOIDTextFormat} provides a simple OID formatter based on a dictionary of object name to
 * object identifier mappings.
 *
 * @author Frank Fock
 * @since 3.5.0
 */
public class DictionaryOIDTextFormat extends SimpleOIDTextFormat {

    private final Map<String, OID> nameToOidMap = new HashMap<>();
    private final TreeMap<OID, String> oidToNameMap = new TreeMap<>();

    /**
     * Creates an empty {@link DictionaryOIDTextFormat} that acts like its superclass {@link SimpleOIDTextFormat}
     * unless dictionary entries are added with {@link #put(String)} or {@link #put(String, String)}.
     * {@code dictionaryOIOTextFormat.parse("ifAdminStatus")} will return {@code new int[] { 1,3,6,1,2,1,2,2,1,7 }} if
     * {@code dictionaryOIOTextFormat.put("ifAdminStatus=1.3.6.1.2.1.2.2.1.7")} was called before. Otherwise,
     * a {@link ParseException} will be thrown.
     * An the other hand, {@code dictionaryOIOTextFormat.format(new int[] { 1,3,6,1,2,1,2,2,1,7,1000 })} will return
     * {@code "ifAdminStatus.1000"} in the first case, i.e. with dictionary entry.
     */
    public DictionaryOIDTextFormat() {
        super();
    }

    /**
     * Create a dictionary based OID formatter from a list of object name to {@link OID} mappings of the form
     * 'sysDescr=1.3.6.1.2.1.1.1'.
     *
     * @param objectNameToDottedNumbers
     *    an object name to OID mapping of the form "&lt;oid&gt;=&lt;object-name&gt;
     */
    public DictionaryOIDTextFormat(String ...objectNameToDottedNumbers) {
        for (String mapping : objectNameToDottedNumbers) {
            put(mapping);
        }
    }

    /**
     * Put an object name to oid mapping into the internal dictionary used for the OID/text formatting.
     * @param objectName
     *    an SMI object name like 'sysDescr'.
     * @param dottedNumbersOidString
     *    the SMI object identifier registered for the given {@code objectName} in dotted number format, e.g.
     *    '1.3.6.1.2.1.1.1' for 'sysDescr'.
     * @return
     *     the parsed {@link OID} or {@code null} if the oid string contains characters other than digits and '.'. In
     *     that case, the dictionary is not changed.
     */
    public OID put(String objectName, String dottedNumbersOidString) {
        OID oid = null;
        try {
            oid = new OID(SimpleOIDTextFormat.parseOID(dottedNumbersOidString));
            nameToOidMap.put(objectName, oid);
            oidToNameMap.put(oid, objectName);
            return oid;
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Put an object name to oid mapping into the internal dictionary used for the OID/text formatting that is parsed
     * from a string of the form 'sysDescr = 1.3.6.1.2.1.1.1' or 'sysDescr=1.3.6.1.2.1.1.1'.
     * @param objectNameEqualsDottedNumberString
     *    a string with an SMI object name, a single equals sign, and after that equals sign a dotted number OID string:
     *    e.g. 'sysDescr=1.3.6.1.2.1.1.1'.
     * @return
     *    the parsed {@link OID} or {@code null} if the oid string contains characters other than digits and '.'. In
     *    that case, the dictionary is not changed.
     */
    public OID put(String objectNameEqualsDottedNumberString) {
        int equalsPos = objectNameEqualsDottedNumberString.indexOf('=');
        return put(objectNameEqualsDottedNumberString.substring(0, equalsPos).trim(),
                   objectNameEqualsDottedNumberString.substring(equalsPos+1).trim());
    }

    /**
     * Return the size of the dictionary.
     * @return
     *    the number of entries in the OID formatting dictionary.
     */
    public int size() {
        return nameToOidMap.size();
    }

    @Override
    public String format(int[] value) {
        if (value == null) {
            return null;
        }
        OID oid = new OID(value);
        String name = oidToNameMap.get(oid);
        if (name != null) {
            return name;
        }
        OID floorKey = oidToNameMap.floorKey(oid);
        while (floorKey != null) {
            if (oid.startsWith(floorKey)) {
                name = oidToNameMap.get(floorKey);
                if (name != null) {
                    return name + "." + SimpleOIDTextFormat.formatOID(oid.subOID(floorKey.size()).getValue());
                }
            }
            floorKey = oidToNameMap.floorKey(floorKey.trim());
        }
        return super.format(value);
    }

    @Override
    public int[] parse(String text) throws ParseException {
        if (text == null) {
            return null;
        }
        if (text.length() > 0 && !Character.isDigit(text.charAt(0))) {
            int dotPos = text.indexOf('.');
            OID oid;
            if (dotPos > 0) {
                String name = text.substring(0, dotPos);
                oid = nameToOidMap.get(name);
                if (oid != null) {
                    return new OID(oid.getValue(), super.parse(text.substring(dotPos+1))).getValue();
                }
            }
            else {
                oid = nameToOidMap.get(text);
            }
            if (oid != null) {
                return oid.getValue();
            }
            return null;
        }
        return super.parse(text);
    }
}
