/*_############################################################################
  _## 
  _##  SNMP4J - EngineBootsCounterFile.java  
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

import java.io.File;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.OctetString;

/**
 * The {@code EngineBootsCounterFile} is a {@link SnmpEngineIdProvider}
 * that stores the boot counter amd the engine ID of an SNMP entity in a file.
 *
 * @author Frank Fock
 * @version 3.5.0
 * @since 3.5.0
 */
public class EngineBootsCounterFile implements SnmpEngineIdProvider {

    private static final LogAdapter logger = LogFactory.getLogger(EngineBootsCounterFile.class);

    private final File bootCounterFile;
    private int boots = -1;
    private OctetString engineID;

    /**
     * Creates the boot counter by using the specified file.
     * @param bootCounterFile
     *    a file (does not have to exists yet but must be writable).
     */
    public EngineBootsCounterFile(File bootCounterFile) {
        this.bootCounterFile = bootCounterFile;
    }

    /**
     * Returns the current engine boot counter value incremented by one.
     *
     * @return the last engine boots counter incremented by one.
     */
    public int updateEngineBoots() {
        boots = getLastEngineBoots();
        boots++;
        if (boots <= 0) {
            boots = 1;
        }
        setEngineBoots(boots);
        return boots;
    }

    /**
     * Reads the engine boots counter from the corresponding input stream (file).
     * @return
     *    the boots counter value read or zero if it could not be read.
     */
    protected int getLastEngineBoots() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(bootCounterFile);
            ObjectInputStream ois = new ObjectInputStream(fis);
            int boots = ois.readInt();
            try {
                Object engineIdObject = ois.readObject();
                if (engineIdObject instanceof OctetString) {
                    this.engineID = (OctetString)engineIdObject;
                }
            } catch (Exception e) {
                logger.warn("Engine boots counter file could not be read: "+e.getMessage());
            }
            if (logger.isInfoEnabled()) {
                logger.info("Engine boots is: "+boots + " for engine ID: "+engineID);
            }
            return boots;
        }
        catch (FileNotFoundException ex) {
            logger.warn("Could not find boot counter file: "+bootCounterFile);
        }
        catch (IOException iox) {
            if (logger.isDebugEnabled()) {
                iox.printStackTrace();
            }
            logger.error("Failed to read boot counter: "+iox.getMessage());
        }
        finally {
            if (fis != null) {
                try {
                    fis.close();
                }
                catch (IOException ex1) {
                    logger.warn(ex1);
                }
            }
        }
        return 0;
    }

    protected void setEngineBoots(int engineBoots) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(bootCounterFile);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeInt(engineBoots);
            oos.writeObject(engineID);
            oos.close();
            if (logger.isInfoEnabled()) {
                logger.info("Wrote boot counter: " + engineBoots+ " for engine ID: "+engineID);
            }
        }
        catch (FileNotFoundException fnfex) {
            logger.error("Boot counter configuration file not found: "+
                    fnfex.getMessage());
        }
        catch (IOException iox) {
            logger.error("Failed to write boot counter: "+iox.getMessage());
        }
        finally {
            if (fos != null) {
                try {
                    fos.close();
                }
                catch (IOException ex1) {
                    logger.warn(ex1);
                }
            }
        }
    }

    public int getEngineBoots() {
        if (boots < 0) {
            boots = getLastEngineBoots();
        }
        return boots;
    }

    public File getBootCounterFile() {
        return bootCounterFile;
    }

    @Override
    public OctetString getEngineId(OctetString defaultEngineID) {
        if (boots < 0) {
            getEngineBoots();
        }
        if (engineID == null) {
            engineID = defaultEngineID;
            setEngineBoots(boots);
            return engineID;
        }
        return engineID;
    }

    @Override
    public void resetEngineId(OctetString engineId) {
        this.engineID = engineId;
    }
}
