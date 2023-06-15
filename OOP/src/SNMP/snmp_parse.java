
import java.io.File;
import java.io.IOException;
import java.util.HashMap;


import net.percederberg.mibble.Mib;
import net.percederberg.mibble.MibLoaderException;
import net.percederberg.mibble.MibSymbol;

import net.percederberg.mibble.*;

import net.percederberg.mibble.value.*;


public class MibParser {
	public static Mib loadMibb(File file)
		    throws MibLoaderException, IOException {

		    // In real code, a single MibLoader instance should be reused
		    MibLoader loader = new MibLoader();

		    // The MIB file may import other MIBs (often in same dir)
		    loader.addDir(file.getParentFile());

		    // Once initialized, MIB loading is straight-forward
		    return loader.load(file);
		}

	
	
	public static ObjectIdentifierValue extractOid(MibSymbol symbol) {
	    if (symbol instanceof MibValueSymbol) {
	        MibValue value = ((MibValueSymbol) symbol).getValue();
	        if (value instanceof ObjectIdentifierValue) {
	            return (ObjectIdentifierValue) value;
	        }
	    }
	    return null;
	}
    public static void main(String[] args) throws MibLoaderException, IOException  {
    	
		try {
			
			Mib mib = loadMibb(new File("/Users/dangminhduc/Desktop/SNMPv2-MIB.mib"));
			
		    HashMap<String,ObjectIdentifierValue> map = new HashMap<>();
		    for (MibSymbol symbol : mib.getAllSymbols()) {
		        ObjectIdentifierValue oid = extractOid(symbol);
		        if (oid != null) {
		        	System.out.println(oid +" : "+ symbol.getName());
		            map.put(symbol.getName(), oid);
		        }
		    }
			    
		} catch (MibLoaderException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
    	
}

}
