package snmpget;

public class TestSnmpGet {
	
	public static void main(String[] args) {

		String ip = "192.168.56.1";
		String community = "public";
		String oidval = "1.3.6.1.2.1.1.1.0";
		SnmpGet.snmpGet(ip,community, oidval);	
	}	
}
