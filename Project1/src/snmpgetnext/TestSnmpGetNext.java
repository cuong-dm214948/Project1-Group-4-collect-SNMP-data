package snmpgetnext;

import java.util.List;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.snmp4j.CommunityTarget;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class TestSnmpGetNext {

	public static final int DEFAULT_VERSION = SnmpConstants.version2c;
	public static final String DEFAULT_PROTOCOL = "udp";
	public static final int DEFAULT_PORT = 161;
	public static final long DEFAULT_TIMEOUT = 3 * 1000L;
	public static final int DEFAULT_RETRY = 3;


	public static CommunityTarget createDefault(String ip, String community) {
		
		Address address = GenericAddress.parse(DEFAULT_PROTOCOL + ":" + ip
					+ "/" + DEFAULT_PORT);
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString(community));
		target.setAddress(address);
		target.setVersion(DEFAULT_VERSION);
		target.setTimeout(DEFAULT_TIMEOUT); // ms
		target.setRetries(DEFAULT_RETRY);
		return target;
	}

	public static void snmpGetNext(String ip, String community, String oid) {
		System.out.println( "-----SNMP query started-----");
		CommunityTarget target = createDefault(ip, community);
		Snmp snmp = null;
		try {
			PDU pdu = new PDU();
			
			pdu.add(new VariableBinding(new OID(oid)));

			DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			snmp.listen();
			
			pdu.setType(PDU.GET);
			ResponseEvent respEvent = snmp.getNext(pdu, target);
			System.out.println("PeerAddress:" + respEvent.getPeerAddress());
			PDU response = respEvent.getResponse();
			if (response == null) {
				System.out.println( "response is null, request time out.");
			} else {
				System.out.println("response pdu size is " + response.size());
				for (int i = 0; i < response.size(); i++) {
					VariableBinding vb = response.get(i);
					System.out.println( vb.getVariable());
					System.out.println( "Total request: " + response.size());
					}
				}
				System.out.println("SNMP GET one OID value finished !");
			} catch (Exception e) {
				e.printStackTrace();
				System.out.println( "SNMP Get Exception:" + e);
			} finally {
				if (snmp != null) {
					try {
						snmp.close();
					} catch (IOException ex1) {
						snmp = null;
					}
				}

			}
		System.out.println( "-----SNMP query finished-----");
		}

	public static void main(String[] args) {

		String ip = "192.168.56.1";
		String community = "public";
		String oidval = "1.3.6.1.2.1.1.2.0";
		TestSnmpGetNext.snmpGetNext(ip,community, oidval);	
	}
}