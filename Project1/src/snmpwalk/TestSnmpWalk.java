package snmpwalk;

public class TestSnmpWalk {
	
	public static void main(String[] args) {
		String ip = "192.168.56.1";
		String community = "public";
		String targetOid = "1.3.6.1.2.1.1";
		SnmpWalk.snmpWalk(ip, community, targetOid);	
	}
}