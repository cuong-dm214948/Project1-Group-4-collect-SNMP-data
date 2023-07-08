package snmpwalk;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SnmpWalk {

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
	private static String result = "";
	public static String snmpWalk(String ip, String community, String targetOid) {
		CommunityTarget target = createDefault(ip, community);
		TransportMapping transport = null;
		Snmp snmp = null;
		
		try {
			transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			transport.listen();

			PDU pdu = new PDU();
			OID targetOID = new OID(targetOid);
			pdu.add(new VariableBinding(targetOID));

			boolean finished = false;
			
			while (!finished) {
				VariableBinding vb = null;
				ResponseEvent respEvent = snmp.getNext(pdu, target);

				PDU response = respEvent.getResponse();
				if (null == response) {
					result += "ResponsePDU == null.\n";
					finished = true;
					break;
				} else {
					vb = response.get(0);
				}
				// check finish
				finished = checkWalkFinished(targetOID, pdu, vb);
				if (!finished) {
//					result += "==== walk each value :\n";
					
					result += vb.getOid() + " = " + vb.getVariable();
					// Set up the variable binding for the next entry.
					pdu.setRequestID(new Integer32(0));
					pdu.set(0, vb);
				} else {
//					result += "SNMP walk OID has finished.\n";
					snmp.close();
				}
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			result += "SNMP walk Exception: " + e;
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

	private static boolean checkWalkFinished(OID targetOID, PDU pdu,
			VariableBinding vb) {
		boolean finished = false;
		if (pdu.getErrorStatus() != 0) {
			result += "[true] responsePDU.getErrorStatus() != 0 \n";
			result += pdu.getErrorStatusText() + "\n";
			finished = true;
		} else if (vb.getOid() == null) {
			result += "[true] vb.getOid() == null\n";
			finished = true;
		} else if (vb.getOid().size() < targetOID.size()) {
			result += "[true] vb.getOid().size() < targetOID.size()\n";
			finished = true;
		} else if (targetOID.leftMostCompare(targetOID.size(), vb.getOid()) != 0) {
			result += "[true] targetOID.leftMostCompare() != 0\n";
			finished = true;
		} else if (Null.isExceptionSyntax(vb.getVariable().getSyntax())) {
			result += "[true] Null.isExceptionSyntax(vb.getVariable().getSyntax())\n";
			finished = true;
		} else if (vb.getOid().compareTo(targetOID) <= 0) {
			result += "[true] Variable received is not "
					+ "lexicographic successor of requested " + "one:\n";
			result += vb.toString() + " <= " + targetOID + "\n";
			finished = true;
		}
		return finished;

	}

	public static void snmpAsynWalk(String ip, String community, String oid) {
		final CommunityTarget target = createDefault(ip, community);
		Snmp snmp = null;
		try {
			System.out.println("----> demo start <----");

			DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			snmp.listen();

			final PDU pdu = new PDU();
			final OID targetOID = new OID(oid);
			final CountDownLatch latch = new CountDownLatch(1);
			pdu.add(new VariableBinding(targetOID));

			ResponseListener listener = new ResponseListener() {
				public void onResponse(ResponseEvent event) {
					((Snmp) event.getSource()).cancel(event.getRequest(), this);

					try {
						PDU response = event.getResponse();
						// PDU request = event.getRequest();
						// System.out.println("[request]:" + request);
						if (response == null) {
							System.out.println("[ERROR]: response is null");
						} else if (response.getErrorStatus() != 0) {
							System.out.println("[ERROR]: response status"
									+ response.getErrorStatus() + " Text:"
									+ response.getErrorStatusText());
						} else {
							System.out
							.println("Received Walk response value :");
							VariableBinding vb = response.get(0);

							boolean finished = checkWalkFinished(targetOID,
									pdu, vb);
							if (!finished) {
								System.out.println(vb.getOid() + " = "
										+ vb.getVariable());
								pdu.setRequestID(new Integer32(0));
								pdu.set(0, vb);
								((Snmp) event.getSource()).getNext(pdu, target,
										null, this);
							} else {
								System.out.println("SNMP Asyn walk OID value success !");
								latch.countDown();
							}
						}
					} catch (Exception e) {
						e.printStackTrace();
						latch.countDown();
					}

				}
			};
			snmp.getNext(pdu, target, null, listener);
			System.out.println("pdu ");

			boolean wait = latch.await(30, TimeUnit.SECONDS);
			System.out.println("latch.await =:" + wait);
			snmp.close();

			System.out.println("----> demo end <----");
		} catch (Exception e) {			
			e.printStackTrace();
		}
			System.out.println("SNMP Asyn Walk Exception:" );
	}
}