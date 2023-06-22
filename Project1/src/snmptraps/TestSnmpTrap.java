package snmptraps;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class TestSnmpTrap {
    public void sendSNMPTrap(String trapReceiverAddress) {
        try {
            // Create Transport Mapping
            TransportMapping<?> transport = new DefaultUdpTransportMapping();

            // Create Snmp instance
            Snmp snmp = new Snmp(transport);

            // Start the transport
            transport.listen();

            // Create the target
            Address targetAddress = GenericAddress.parse(trapReceiverAddress);
            CommunityTarget target = new CommunityTarget();
            target.setAddress(targetAddress);
            target.setVersion(SnmpConstants.version2c); // Use the appropriate SNMP version
            target.setCommunity(new OctetString("public")); // Replace with the actual community string

            // Create the PDU
            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);

            // Add the necessary objects to the PDU
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new OctetString("0"))); // System uptime
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.4.1.12345"))); // Trap OID
            pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.3.0"), new OctetString("0"))); // Object with value 0

            // Send the trap
            ResponseEvent response = snmp.send(pdu, target);

            // Print the response
            if (response != null && response.getResponse() != null) {
                System.out.println("Response: " + response.getResponse().get(0).getVariable());
            }

            // Close the SNMP session
            snmp.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

