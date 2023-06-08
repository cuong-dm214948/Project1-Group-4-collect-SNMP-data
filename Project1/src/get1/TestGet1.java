package get1;

import java.util.ArrayList;
import java.util.List;




public class TestGet1 {
	
	public static void main(String[] args) {

		String ip = "192.168.56.1";
		String community = "public";
		String oidval = "1.3.6.1.2.1.1.1.0";
		Get1.snmpGet(ip,community, oidval);
		
		
		List<String> oidList=new ArrayList<String>();
		oidList.add("1.3.6.1.2.1.1.5.0");
		oidList.add("1.3.6.1.2.1.1.7.0");
		Get1.snmpGetList(ip, community, oidList);
		
		
		oidList.add("1.3.6.1.2.1");
		oidList.add("1.3.6.1.2.12");
		Get1.snmpAsynGetList(ip, community, oidList);
		

		String targetOid = "1.3.6.1.4.1.37014.8000.2.4.1";
		Get1.snmpWalk(ip, community, targetOid);

	}
	
}
