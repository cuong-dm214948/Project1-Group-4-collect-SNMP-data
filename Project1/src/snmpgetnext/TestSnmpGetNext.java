package snmpgetnext;

public class TestSnmpGetNext {
	public static void main(String[] args) {

		String ip = "192.168.56.1";
		String community = "public";
		String oidval = "1.3.6.1.2.1.1.2.0";
		SnmpGetNext.snmpGetNext(ip,community, oidval);	
	}
}