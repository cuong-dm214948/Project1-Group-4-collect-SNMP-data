package snmpgetnext;

import java.io.IOException;

import org.snmp4j.CommunityTarget;
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

public class SnmpGetNext {

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

	public static String snmpGetNext(String ip, String community, String oid) {
		String result = "";
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
//			System.out.println("PeerAddress:" + respEvent.getPeerAddress());
			PDU response = respEvent.getResponse();
			if (response == null) {
				result += "Response is null, request time out.\n";
			} else {
//				System.out.println("response pdu size is " + response.size());
				for (int i = 0; i < response.size(); i++) {
					VariableBinding vb = response.get(i);
					result += vb.getVariable() +"\n";
					}
				}
//				System.out.println("SNMP GET one OID value finished !");
			} catch (Exception e) {
//				e.printStackTrace();
				result += "SNMP Get Exception:" + e.getMessage()+".\n";
			} finally {
				if (snmp != null) {
					try {
						snmp.close();
					} catch (IOException ex1) {
						snmp = null;
					}
				}

			}
		return result;
		}
}
