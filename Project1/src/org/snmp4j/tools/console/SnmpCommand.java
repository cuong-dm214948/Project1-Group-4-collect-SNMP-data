/*_############################################################################
  _## 
  _##  SNMP4J - SnmpCommand.java  
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
package org.snmp4j.tools.console;

import org.snmp4j.*;
import org.snmp4j.asn1.BER;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.security.nonstandard.PrivAES192With3DESKeyExtension;
import org.snmp4j.security.nonstandard.PrivAES256With3DESKeyExtension;
import org.snmp4j.smi.*;
import org.snmp4j.transport.*;
import org.snmp4j.util.*;
import org.snmp4j.util.ArgumentParser.ArgumentFormat;
import org.snmp4j.util.ArgumentParser.ArgumentParseException;
import org.snmp4j.util.SnmpConfigurator.InnerPDUFactory;
import org.snmp4j.version.VersionInfo;

import java.io.*;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.*;
import java.util.Map.Entry;

public class SnmpCommand implements Runnable, CommandResponder, TransportListener {


    // initialize Java logging
    static {
        LogFactory.setLogFactory(new ConsoleLogFactory());
        BER.setCheckSequenceLength(false);
    }

    private static final String OPTIONS =
            "+d[s{=off}<(?i)(off|error|warn|info|debug)>] +Dn +s +f[s{=3}<(1|2|3|4)>] ";
    private static final String CONSOLE_OPTIONS =
            "+w[i{=79}] +h[i{=0}] ";
    private static final String V3_AUTH_PRIV_PROTOCOL =
            "+a[s<MD5|SHA|SHA224|SHA256|SHA384|SHA512>] +y[s<DES|3DES|AES128|AES192|AES256|AES192p|AES256p>] ";
    private static final String V3_OPTIONS = V3_AUTH_PRIV_PROTOCOL +
            "+A[s] +bc[i{=0}] +e[x] +E[x] -rsl[s{=low}<(low|basic|secure)>] " +
            "+Y[s] +u[s] +l[x] +n[s] ";
    private static final String TRAP_OPTIONS =
            "+Ta[s{=0.0.0.0}<(\\d){1,3}\\.(\\d){1,3}\\.(\\d){1,3}\\.(\\d){1,3}>] " +
                    "-To[s{=1.3.6.1.6.3.1.1.5.1}<([a-zA-Z\\-0-9]*:)?[0-9a-zA-Z\\-\\.]*>] " +
                    "+Te[s{=0.0}<([a-zA-Z\\-0-9]*:)?[0-9a-zA-Z\\-\\.]*>] " +
                    "+Ts[i{=0}] +Tg[i{=0}] +Tu[l{=0}] ";
    private static final String TLS_OPTIONS =
            "+tls-trust-ca[s] +tls-peer-id[s] +tls-local-id[s] +tls-version[s{=TLSv1}<(TLSv1|TLSv1.1|TLSv1.2)>] " +
                    "+dtls-version["+SnmpConfigurator.F_DTLS_VERSION+"] "+
                    "+Djavax.net.ssl.keyStore +Djavax.net.ssl.keyStorePassword " +
                    "+Djavax.net.ssl.trustStore +Djavax.net.ssl.trustStorePassword ";
    private static final String SNMP_OPTIONS =
            "+b["+SnmpConfigurator.F_BIND_ADDRESS+"] +c[s] +r[i{=1}] +t[i{=5000}] +v[s{=3}<1|2c|3>] +Ors[i{=65535}] +p ";
    private static final String SNMPV3_ONLY_OPTIONS =
            "+c[s] +r[i{=1}] +t[i{=5000}] +v[s{=3}<3>] +Ors[i{=65535}] +p ";
    private static final String BULK_OPTIONS =
            "-Cr[i{=10}] -Cn[i{=0}] ";
    private static final String TABLE_OPTIONS =
            "+Cil[s] +Ciu[s] +Ch +Ci +Cl +Cw[i] +Cf[s] +Cc[i] " +
                    "+Otd +OtCSV +OttCSV ";
    private static final String WALK_OPTIONS =
            "+ilo ";

    private static final String ADDRESS_PARAMETER =
            "#address["+SnmpConfigurator.F_BIND_ADDRESS+"] ";

    private static final String OID_PARAMETER =
            "#OID[s<([A-Z]+[a-zA-Z\\-0-9]*:)?([a-z][a-zA-Z\\-0-9])?([0-9]+[\\.][0-9]+)?[^=]*(=(\\{[iusxdnotab]\\})?.*)?>] ";

    private static final String OPT_OID_PARAMETER =
            "+OID[s<([a-zA-Z\\-0-9]*:)?[0-9a-zA-Z\\-\\.#]*(=(\\{[iusxdnotab]\\})?.*)?>] ";

    private static final String OIDLIST_PARAMETER =
            OID_PARAMETER + ".. ";

    private static final String OPT_OIDLIST_PARAMETER =
            OPT_OID_PARAMETER + ".. ";

    private static final String ALL_OPTIONS = CONSOLE_OPTIONS +
            OPTIONS + V3_OPTIONS + TLS_OPTIONS + TRAP_OPTIONS +
            SNMP_OPTIONS + BULK_OPTIONS + TABLE_OPTIONS + WALK_OPTIONS;

    private static final String[][] COMMANDS = {

            {
            "set",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS,
            "#command[s<set>] " + ADDRESS_PARAMETER + OIDLIST_PARAMETER
    }, {
            "get",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS ,
            "#command[s<get>] " + ADDRESS_PARAMETER + OIDLIST_PARAMETER
    }, {
            "getnext",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS,
            "#command[s<getnext>] " + ADDRESS_PARAMETER + OIDLIST_PARAMETER
    }, {
            "getbulk",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS + BULK_OPTIONS,
            "#command[s<getbulk>] " + ADDRESS_PARAMETER + OIDLIST_PARAMETER
    }, {
            "inform",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS + TRAP_OPTIONS,
            "#command[s<inform>] " + ADDRESS_PARAMETER + OPT_OIDLIST_PARAMETER
    }, {
            "trap",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS + TRAP_OPTIONS,
            "#command[s<trap>] " + ADDRESS_PARAMETER + OPT_OIDLIST_PARAMETER
    }, {
            "v1trap",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + TRAP_OPTIONS,
            "#command[s<v1trap>] " + ADDRESS_PARAMETER + OPT_OIDLIST_PARAMETER
    }, {
            "table",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS + BULK_OPTIONS +
                    TABLE_OPTIONS,
            "#command[s<table>] " + ADDRESS_PARAMETER + OIDLIST_PARAMETER
    }, {
            "walk",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS + BULK_OPTIONS +
                    TABLE_OPTIONS + WALK_OPTIONS,
            "#command[s<walk>] " + ADDRESS_PARAMETER + OID_PARAMETER
    }, {
            "dump-snapshot",
            OPTIONS + CONSOLE_OPTIONS,
            "#command[s<dump-snapshot>] #file[s]"
    }, {
            "create-snapshot",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS + BULK_OPTIONS +
                    TABLE_OPTIONS + WALK_OPTIONS,
            "#command[s<create-snapshot>] #file[s] " + ADDRESS_PARAMETER + OID_PARAMETER
    }, {
            "listen",
            OPTIONS + CONSOLE_OPTIONS + SNMP_OPTIONS + V3_OPTIONS + TLS_OPTIONS,
            "#command[s<listen>] " + ADDRESS_PARAMETER
    }, {
            "help",
            OPTIONS + CONSOLE_OPTIONS,
            "#command[s<help>] +subject[s<all|create-snapshot|defaults|dump-snapshot|" +
                    "get|getbulk|getnext|inform|license|listen|oid|mib|" +
                    "set|smi|table|trap|usmKey|usmUser|v1trap|version|walk>]"
    }, {
            "example",
            OPTIONS + CONSOLE_OPTIONS,
            "#command[s<example>] +subject[s<create-snapshot|defaults|dump-snapshot|" +
                    "get|getbulk|getnext|inform|license|listen|oid|mib|" +
                    "set|smi|table|trap|v1trap|version|walk>]"
    }, {
            "version",
            OPTIONS + CONSOLE_OPTIONS,
            "#command[s<version>]"
    }
    };

    private static final int DEFAULT = 0;
    private static final int WALK = 1;
    private static final int LISTEN = 2;
    private static final int TABLE = 3;
    private static final int CVS_TABLE = 4;
    private static final int TIME_BASED_CVS_TABLE = 5;
    private static final int SNAPSHOT_CREATION = 6;
    private static final int SNAPSHOT_DUMP = 7;
    private static final int OID_FIND = 8;
    private static final int SMI_DUMP = 9;
    private static final int OP_USM_USER = 10;
    private static final int OP_USM_KEY = 11;
    private static final int OP_USM_DH_KEY = 12;
    private static final int OP_USM_DH_KICKSTART_INIT = 13;
    private static final int OP_USM_DH_KICKSTART_RUN = 14;

    private static boolean packetDumpEnabled = false;

    Target<?> target;
    OID authProtocol;
    OID privProtocol;
    OctetString privPassphrase;
    OctetString authPassphrase;
    OctetString community = new OctetString("public");
    OctetString authoritativeEngineID;
    OctetString contextEngineID;
    OctetString contextName = new OctetString();
    OctetString securityName = new OctetString();
    OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());

    TimeTicks sysUpTime = new TimeTicks(0);
    OID trapOID = SnmpConstants.coldStart;

    int version = SnmpConstants.version3;
    int engineBootCount = 0;
    int retries = 1;
    int timeout = 1000;
    int pduType = PDU.GETNEXT;
    int maxSizeResponsePDU = 65535;
    Vector<VariableBinding> vbs = new Vector<VariableBinding>();
    File snapshotFile;

    protected int operation = DEFAULT;

    int numDispatcherThreads = 2;

    boolean useDenseTableOperation = false;

    private static int stdoutWidth = 79;

    // table options
    OID lowerBoundIndex, upperBoundIndex;

    PDUFactory pduFactory;
    Snmp snmp;
    Map<String,List<Object>> settings;
    String command;

    private static PrintStream err = new FilterPrintStream(System.err);
    private static PrintStream out = System.out;

    private static ResourceBundle help = ResourceBundle.getBundle("org.snmp4j.tools.console.help");
    private static int[] tabs = null;
    private static boolean silent = false;

    private int returnCode = 0;

    public SnmpCommand(String command, Map<String, List<Object>> args) throws IOException {

        this.command = command;
        this.settings = args;
        if (!"help".equals(command) && (!"example".equals(command)) &&
                (!"license".equals(command)) && (!"oid".equals(command)) &&
                (!"smi".equals(command))) {
            if ("usmUser".equals(command) || "usmKey".equals(command) ||
                    "usmDHKey".equals(command) || "usmDHKickstartRun".equals(command)) {
                args.put("v", Collections.singletonList("3"));
            }
            SnmpConfigurator snmpConfig = new SnmpConfigurator();
            target = snmpConfig.getTarget(args);

            Address bindAddress = snmpConfig.getBindAddress(args);
            AbstractTransportMapping<? extends Address> transport = null;
            if (bindAddress == null) {
                if (target.getAddress() instanceof TlsAddress) {
                    transport = new TLSTM();
                } else if (target.getAddress() instanceof DtlsAddress) {
                    transport = new DTLSTM();
                } else if (target.getAddress() instanceof TcpAddress) {
                    transport = new DefaultTcpTransportMapping();
                } else {
                    transport = new DefaultUdpTransportMapping();
                }
            }
            else if (target.getAddress() != null && bindAddress.getClass().equals(target.getAddress().getClass())) {
                if (target.getAddress() instanceof TlsAddress) {
                    transport = new TLSTM((TlsAddress)bindAddress);
                } else if (target.getAddress() instanceof DtlsAddress) {
                    transport = new DTLSTM((DtlsAddress)bindAddress);
                } else if (target.getAddress() instanceof TcpAddress) {
                    transport = new DefaultTcpTransportMapping((TcpAddress)bindAddress);
                } else {
                    transport = new DefaultUdpTransportMapping((UdpAddress)bindAddress);
                }
            }
            else {
                System.err.println("Bind address type "+bindAddress+
                        " does not match target address type "+target.getAddress()+", aborting");
                System.exit(2);
            }
            if (args.containsKey("p")) {
                packetDumpEnabled = true;
            }
            SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.noAuthNoPrivIfNeeded);
            if (args.containsKey("rsl")) {
                String strategy = (String) ArgumentParser.getValue(settings, "rsl", 0);
                if ((strategy != null) && ("basic".indexOf(strategy) == 0)) {
                    SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.standard);
                } else if ((strategy != null) && ("secure".indexOf(strategy) == 0)) {
                    SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.neverNoAuthNoPriv);
                }
            }
            // Set the default counter listener to return proper USM and MP error
            // counters.
            CounterSupport.getInstance().addCounterListener(new
                    DefaultCounterListener());
            SnmpCommandMessageDispatcher bmd = new SnmpCommandMessageDispatcher();
            bmd.addCommandResponder(this);
            bmd.addMessageProcessingModel(new MPv2c());
            bmd.addMessageProcessingModel(new MPv1());
            bmd.addMessageProcessingModel(new MPv3());
            SecurityProtocols.getInstance().addDefaultProtocols();
            SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256With3DESKeyExtension());
            SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192With3DESKeyExtension());
            snmp = new Snmp(bmd, transport);
            if ((args.containsKey("v")) &&
                    ("3".equals(ArgumentParser.getValue(settings, "v", 0)))) {
                MPv3 mpv3 = (MPv3) snmp.getMessageProcessingModel(MPv3.ID);
                if (target.getSecurityModel() == SecurityModel.SECURITY_MODEL_USM) {
                    SecurityModels.getInstance().addSecurityModel(
                            new USM(SecurityProtocols.getInstance(),
                                    new OctetString(mpv3.getLocalEngineID()),
                                    0));
                } else if (target.getSecurityModel() == SecurityModel.SECURITY_MODEL_TSM) {
                    OctetString localEngineID =
                            SnmpConfigurator.createOctetString((String)
                                            ArgumentParser.getValue(settings, "l", 0),
                                    null);
                    if (localEngineID == null) {
                        SecurityModels.getInstance().addSecurityModel(new TSM(new OctetString(mpv3.getLocalEngineID()), false));
                    } else {
                        SecurityModels.getInstance().addSecurityModel(new TSM(localEngineID, false));
                    }
                }
            }
            snmpConfig.configure(snmp, args);
            snmp.listen();
            pduType = PDU.getTypeFromString(command.toUpperCase());
            if (pduType == Integer.MIN_VALUE) {
                pduType = PDU.GETNEXT;
            }
            args.put("o", Arrays.asList(PDU.getTypeString(pduType)));
            pduFactory = snmpConfig.getPDUFactory(args);
            pduType = pduFactory.createPDU(target).getType();

            assignOptions(args);
        }
    }


    private void assignOptions(Map<String,List<Object>> args) {
        if ("walk".equals(command)) {
            operation = WALK;
        } else if ("create-snapshot".equals(command)) {
            operation = SNAPSHOT_CREATION;
            snapshotFile = new File((String) ArgumentParser.getValue(args, "file", 0));
            if (!snapshotFile.canWrite() && snapshotFile.exists()) {
                throw new IllegalArgumentException("Snapshot file '" + snapshotFile +
                        "' cannot be written");
            }
        } else if ("dump-snapshot".equals(command)) {
            operation = SNAPSHOT_DUMP;
            snapshotFile = new File((String) ArgumentParser.getValue(args, "file", 0));
            if (!snapshotFile.canRead()) {
                throw new IllegalArgumentException("Snapshot file '" + snapshotFile +
                        "' cannot be read");
            }
        } else if ("listen".equals(command)) {
            operation = LISTEN;
        } else if ("table".equals(command)) {
            operation = TABLE;
            if (args.containsKey("OtCSV")) {
                operation = CVS_TABLE;
            } else if (args.containsKey("OttCSV")) {
                operation = TIME_BASED_CVS_TABLE;
            }
            if (args.containsKey("Otd")) {
                useDenseTableOperation = true;
            }
        }
        parseOIDs(args);
        checkTrapVariables(this.vbs, pduType, trapOID, sysUpTime);
    }

    private void parseOIDs(Map<String,List<Object>> args) throws IllegalArgumentException {
        List<Object> oids = args.get("OID");
        if (oids != null) {
            int i = 1;
            for (Iterator<?> it = oids.iterator(); it.hasNext(); i++) {
                String oid = (String) it.next();
                char type = 'i';
                String value = null;
                int equal = oid.indexOf("=");
                if (equal > 0) {
                    if (!oid.contains("={")) {
                        type = 0;
                    } else {
                        type = oid.charAt(equal + 2);
                    }
                    value = oid.substring(((type == 0) ? equal : oid.indexOf('}')) + 1);
                    oid = oid.substring(0, equal);
                } else if (oid.indexOf('#') > oid.indexOf(':') + 1) {
                    StringTokenizer st = new StringTokenizer(oid, "#");
                    if (st.countTokens() != 2) {
                        throw new IllegalArgumentException("Illegal OID range specified: '" +
                                oid);
                    }
                    oid = st.nextToken();
                    VariableBinding vbLower = new VariableBinding(new OID(oid));
                    vbs.add(vbLower);
                    OID lastOID = new OID(st.nextToken());
                    long last = lastOID.last();
                    long first = vbLower.getOid().lastUnsigned();
                    for (long k = first + 1; k <= last; k++) {
                        OID nextOID = new OID(vbLower.getOid().getValue(), 0,
                                vbLower.getOid().size() - 1);
                        nextOID.appendUnsigned(k);
                        VariableBinding next = new VariableBinding(nextOID);
                        vbs.add(next);
                    }
                    continue;
                }
                try {
                    OID o = new OID(oid);
                    VariableBinding vb = new VariableBinding(o);
                    if (type == 0) {
                        Variable variable = null;
                        try {
                            variable =
                                    SNMP4JSettings.getVariableTextFormat().parse(vb.getOid(),
                                            value);
                        } catch (ParseException ex) {
                            ex.printStackTrace();
                        }
                        vb.setVariable(variable);
                    } else {
                        if (value != null) {
                            Variable variable;
                            switch (type) {
                                case 'i':
                                    variable = new Integer32(Integer.parseInt(value));
                                    break;
                                case 'u':
                                    variable = new UnsignedInteger32(Long.parseLong(value));
                                    break;
                                case 's':
                                    variable = new OctetString(value);
                                    break;
                                case 'x':
                                    variable = OctetString.fromString(value, ':', 16);
                                    break;
                                case 'd':
                                    variable = OctetString.fromString(value, '.', 10);
                                    break;
                                case 'b':
                                    variable = OctetString.fromString(value, ' ', 2);
                                    break;
                                case 'n':
                                    variable = new Null();
                                    break;
                                case 'o':
                                    variable = new OID(value);
                                    break;
                                case 't':
                                    variable = new TimeTicks(Long.parseLong(value));
                                    break;
                                case 'a':
                                    variable = new IpAddress(value);
                                    break;
                                default:
                                    throw new IllegalArgumentException("Variable type " + type +
                                            " not supported");
                            }
                            vb.setVariable(variable);
                        }
                    }
                    vbs.add(vb);
                } catch (IllegalArgumentException ex) {
                    throw new IllegalArgumentException("OID #" + i + "='" + oid +
                            "': The value '" + value +
                            "' could not be parsed");
                } catch (Exception pex) {
//          pex.printStackTrace();
                    if (pex.getMessage() != null)
                        throw new IllegalArgumentException("OID #" + i + "='" + oid +
                                "' could not be resolved" +
                                ((pex.getMessage() != null) ? ", reason: " + pex.getMessage() : ""));
                }
            }
        }
    }

    private void addUsmUser(Snmp snmp) {
        snmp.getUSM().addUser(securityName, new UsmUser(securityName,
                authProtocol,
                authPassphrase,
                privProtocol,
                privPassphrase));
    }

    public String help(String prefix, String command,
                       boolean listOptionsDetails, boolean withDescription) {
        if (prefix == null) {
            prefix = "";
        }
        StringBuffer buf = new StringBuffer();
        if ((command == null) || ("all".equals(command))) {
            String usage = help.getString("usage.text");
            String version = VersionInfo.getVersion();
            buf.append(MessageFormat.format(usage, version));
            TreeMap<String, ArgumentFormat> options = new TreeMap<String, ArgumentFormat>();
            TreeMap<String, String[]> commands = new TreeMap<String, String[]>();
            for (String[] COMMAND : COMMANDS) {
                String c = COMMAND[0];
                String[] format = selectFormat(c);
                commands.put(c, format);
            }
            for (Entry<String, String[]> stringEntry : commands.entrySet()) {
                String c = stringEntry.getKey();
                String[] format = stringEntry.getValue();
                ArgumentParser p = new ArgumentParser(format[0], format[1]);
                Map<String, ArgumentFormat> o = p.getOptionFormat();
                options.putAll(o);
                buf.append(c).append(":\n");
                buf.append(help("", c, false, (command != null)));
                buf.append('\n');
            }
            buf.append("\n\nOPTIONS:\n");
            optionDetailList(getTabPosition(0), prefix, buf, options);
        } else {
            String syn = help.getString("command.syn." + prefix + command);
            String des = help.getString("command.des." + prefix + command);
            if (syn != null && des != null) {
                String line = "";
                if (!"".equals(syn)) {
                    line += tab(0, 0, 0) + syn;
                    line += (withDescription) ? "\n\n" : "\n";
                }
                if (withDescription) {
                    int firstLineIndent = 0;
                    if (line.length() >= getTabPosition(0)) {
                        line += '\n';
                        firstLineIndent = getTabPosition(0);
                    }
                    line += format(getTabPosition(0), des, 0, firstLineIndent);
                }
                buf.append(line);
                buf.append('\n');
            }
            try {
                String subcmd = help.getString("command.sub." + prefix + command);
                String[] subcmds = subcmd.split(",");
                for (int i = 0; i < subcmds.length; i++) {
                    if (i == 0) {
                        buf.append("\n");
                    }
                    buf.append(spaces(getTabPosition(0)));
                    buf.append(subcmds[i]).append((withDescription) ? ":\n" : "");
                    buf.append(help(command + ".", subcmds[i], false, withDescription));
                }
            } catch (MissingResourceException mrex) {
                // ignore
            }
            String od = "";
            if (listOptionsDetails) {
                od = options(getTabPosition(0), prefix, command);
            } else if ("".equals(prefix)) {
                od = optionList(getTabPosition(0), prefix, command);
            }
            if (od.length() > 0) {
                buf.append('\n');
                buf.append(spaces(getTabPosition(0)));
                buf.append("Options:\n");
                buf.append(od);
            }
            buf.append('\n');
        }
        return buf.toString();
    }

    public String example(String prefix, String command) {
        if (prefix == null) {
            prefix = "";
        }
        StringBuilder buf = new StringBuilder();
        String syn = help.getString("command.syn." + prefix + command);
        String des = help.getString("command.des." + prefix + command);
        String exa = null;
        try {
            exa = help.getString("command.exa." + prefix + command);
        } catch (MissingResourceException mrex) {
            //ignore
        }
        String line = syn;
        line += "\n\n";
        line += format(0, des, 0, 0);
        buf.append(line);
        String od = options(0, prefix, command);
        if (od.length() > 0) {
            buf.append('\n');
//        buf.append(spaces(getTabPosition(0)));
            buf.append("Options:\n");
            buf.append(od);
        }
        buf.append('\n');
        if (exa != null) {
//        buf.append(spaces(getTabPosition(0)));
            buf.append("Examples:\n");
            buf.append(format(0, exa, 0, 0));
        }
        return buf.toString();
    }

    private String optionList(int indentation, String prefix, String command) {
        if (prefix != null) {
            return "";
        }
        StringBuilder buf = new StringBuilder();
        String[] format = selectFormat(command);
        if (format == null) {
            return "";
        }
        ArgumentParser p = new ArgumentParser(format[0], format[1]);
        Map<String, ArgumentFormat> options = p.getOptionFormat();
        SortedMap<String, ArgumentFormat> soptions = new TreeMap<>(options);
        for (Iterator<String> it = soptions.keySet().iterator(); it.hasNext(); ) {
            String opt = it.next();
            buf.append("-").append(opt);
            if (it.hasNext()) {
                buf.append(", ");
            }
        }
        return format(indentation, buf.toString(), 0, 0);
    }

    private String options(int indentation, String prefix, String command) {
        StringBuffer buf = new StringBuffer();
        String[] format = selectFormat(command);
        if (format == null) {
            return "";
        }
        ArgumentParser p = new ArgumentParser(format[0], format[1]);
        Map<String, ArgumentFormat> options = p.getOptionFormat();
        SortedMap<String, ArgumentFormat> soptions =
                new TreeMap<String, ArgumentFormat>(options);
        optionDetailList(indentation, prefix, buf, soptions);
        return buf.toString();
    }

    private void optionDetailList(int indentation, String prefix,
                                  StringBuffer buf, SortedMap<String, ArgumentFormat> soptions) {
        for (String opt : soptions.keySet()) {
            String o = spaces(indentation) + "-" + opt;
            String optSyn = help.getString("options.syn." + opt);
            o += tab(indentation, o.length(), 2);
            o += optSyn;
            buf.append(prefix);
            buf.append(o);
            String optDesc = help.getString("options.des." + opt);
            buf.append(format(getTabPosition(3), optDesc, 3, o.length()));
            buf.append('\n');
        }
    }

    private String[] selectFormat(String command) {
        for (int i = 0; i < COMMANDS.length; i++) {
            if (COMMANDS[i][0].equals(command)) {
                return new String[]{COMMANDS[i][1], COMMANDS[i][2]};
            }
        }
        return null;
    }

    private static String tab(int offset, int position, int tabNo) {
        StringBuffer buf = new StringBuffer();
        if (tabs == null) {
            String tabString = help.getString("tabs");
            String[] tabsArray = tabString.split(",");
            tabs = new int[tabsArray.length];
            for (int i = 0; i < tabsArray.length; i++) {
                tabs[i] = Integer.parseInt(tabsArray[i]);
            }
        }
        int t = getTabPosition(tabNo);
        buf.append(spaces(Math.max(1, t + offset - position)));
        return buf.toString();
    }

    private static int getTabPosition(int tabNo) {
        return (tabNo < tabs.length) ?
                tabs[tabNo] : tabs[tabs.length - 1] + (tabNo - tabs.length) * 8;
    }

    private static String format(int indentation, String s, int tabNo,
                                 int firstLineOffset) {
        StringTokenizer st = new StringTokenizer(s, "\t\n", true);
        StringBuffer buf = new StringBuffer();
        int lineLength = firstLineOffset;
        boolean firstLine = true;
        for (int i = 0; st.hasMoreTokens(); i++) {
            String t = st.nextToken();
            if ("\t".equals(t)) {
                String spaces = tab(indentation, lineLength, tabNo++);
                buf.append(spaces);
                lineLength += spaces.length();
            } else if ("\n".equals(t)) {
                tabNo = 0;
                firstLine = false;
                lineLength = 0;
                buf.append("\n");
            } else {
                if ((firstLineOffset > 0) && firstLine) {
                    String l = tab(0, firstLineOffset, tabNo);
                    buf.append(l);
                    lineLength += l.length();
                } else if ((lineLength == 0) && (indentation > 0)) {
                    String l = spaces(indentation);
                    buf.append(l);
                    lineLength += l.length();
                }
                buf.append(wrap(indentation, t, stdoutWidth, lineLength));
                lineLength += t.length();
            }
        }
        return buf.toString();
    }

    private static String wrap(int offset, String s, int maxLineLength,
                               int firstLineOffset) {
        StringTokenizer st = new StringTokenizer(s, " ", true);
        StringBuilder buf = new StringBuilder(s.length());
        int ll = firstLineOffset;
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            if (ll + t.length() > maxLineLength) {
                buf.append('\n');
                if (offset > 0) {
                    buf.append(spaces(offset));
                }
                if (!" ".equals(t)) {
                    buf.append(t);
                    ll = t.length() + offset;
                } else {
                    ll = offset;
                }
            } else {
                buf.append(t);
                ll += t.length();
            }
        }
        return buf.toString();
    }

    public static String spaces(int n) {
        StringBuilder buf = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            buf.append(' ');
        }
        return buf.toString();
    }

    public PDU send() throws IOException {
        PDU request = pduFactory.createPDU(target);
        for (VariableBinding vb : vbs) {
            request.add(vb);
        }

        PDU response = null;
        if ((operation == WALK) || (operation == SNAPSHOT_CREATION)) {
            ArrayList<VariableBinding> snapshot = null;
            if (operation == SNAPSHOT_CREATION) {
                snapshot = new ArrayList<VariableBinding>();
            }
            walk(snmp, request, target, snapshot);
            if (snapshot != null) {
                createSnapshot(snapshot);
            }
            return null;
        } else {
            ResponseEvent<?> responseEvent;
            long startTime = System.currentTimeMillis();
            responseEvent = snmp.send(request, target);
            if (responseEvent != null) {
                response = responseEvent.getResponse();
                err.println("Received response after " +
                        (System.currentTimeMillis() - startTime) + " millis");
            }
        }
        snmp.close();
        return response;
    }

    private void checkTrapVariables(List<VariableBinding> vbs, int pduType, OID trapOID, TimeTicks sysUpTime) {
        if ((pduType == PDU.INFORM) ||
                (pduType == PDU.TRAP)) {
            if ((vbs.size() == 0) ||
                    ((vbs.size() >= 1) &&
                            (!(vbs.get(0)).getOid().equals(SnmpConstants.sysUpTime)))) {
                vbs.add(0, new VariableBinding(SnmpConstants.sysUpTime, sysUpTime));
            }
            if ((vbs.size() == 1) ||
                    ((vbs.size() > 2) &&
                            (!(vbs.get(1)).getOid().equals(SnmpConstants.snmpTrapOID)))) {
                vbs.add(1, new VariableBinding(SnmpConstants.snmpTrapOID, trapOID));
            }
        }
    }

    protected static void printReport(PDU response) {
        if (response.size() < 1) {
            out.println("REPORT PDU does not contain a variable binding.");
            return;
        }

        VariableBinding vb = response.get(0);
        OID oid = vb.getOid();
        if (SnmpConstants.usmStatsUnsupportedSecLevels.equals(oid)) {
            out.print("REPORT: Unsupported Security Level.");
        } else if (SnmpConstants.usmStatsNotInTimeWindows.equals(oid)) {
            out.print("REPORT: Message not within time window.");
        } else if (SnmpConstants.usmStatsUnknownUserNames.equals(oid)) {
            out.print("REPORT: Unknown user name.");
        } else if (SnmpConstants.usmStatsUnknownEngineIDs.equals(oid)) {
            out.print("REPORT: Unknown engine id.");
        } else if (SnmpConstants.usmStatsWrongDigests.equals(oid)) {
            out.print("REPORT: Wrong digest.");
        } else if (SnmpConstants.usmStatsDecryptionErrors.equals(oid)) {
            out.print("REPORT: Decryption error.");
        } else if (SnmpConstants.snmpUnknownSecurityModels.equals(oid)) {
            out.print("REPORT: Unknown security model.");
        } else if (SnmpConstants.snmpInvalidMsgs.equals(oid)) {
            out.print("REPORT: Invalid message.");
        } else if (SnmpConstants.snmpUnknownPDUHandlers.equals(oid)) {
            out.print("REPORT: Unknown PDU handler.");
        } else if (SnmpConstants.snmpUnavailableContexts.equals(oid)) {
            out.print("REPORT: Unavailable context.");
        } else if (SnmpConstants.snmpUnknownContexts.equals(oid)) {
            out.print("REPORT: Unknown context.");
        } else {
            out.print("REPORT contains unknown OID ("
                    + oid.toString() + ").");
        }
        out.println(" Current counter value is " +
                vb.getVariable().toString() + ".");
    }

    public synchronized <A extends Address> void processPdu(CommandResponderEvent<A> e) {
        PDU command = e.getPDU();
        if (command != null) {
            if ((command.getType() != PDU.TRAP) &&
                    (command.getType() != PDU.V1TRAP) &&
                    (command.getType() != PDU.REPORT) &&
                    (command.getType() != PDU.RESPONSE)) {
                out.println(command.toString());
                command.setErrorIndex(0);
                command.setErrorStatus(0);
                command.setType(PDU.RESPONSE);
                StatusInformation statusInformation = new StatusInformation();
                StateReference<?> ref = e.getStateReference();
                try {
                    e.getMessageDispatcher().returnResponsePdu(e.
                                    getMessageProcessingModel(),
                            e.getSecurityModel(),
                            e.getSecurityName(),
                            e.getSecurityLevel(),
                            command,
                            e.getMaxSizeResponsePDU(),
                            ref,
                            statusInformation);
                } catch (MessageException ex) {
                    err.println("Error while sending response: " + ex.getMessage());
                    LogFactory.getLogger(SnmpCommand.class).error(ex);
                }
            }
        }
    }

    protected static void printVariableBindings(PDU response) {
        for (int i = 0; i < response.size(); i++) {
            VariableBinding vb = response.get(i);
            out.println(vb.toString());
        }
    }

    public int table() throws IOException {
        TableUtils tableUtils = new TableUtils(snmp, pduFactory);
        Integer maxRep = ((InnerPDUFactory) pduFactory).getMaxRepetitions();
        if (maxRep != null) {
            tableUtils.setMaxNumRowsPerPDU(maxRep);
        }
        Counter32 counter = new Counter32();

        OID[] columns = new OID[vbs.size()];
        for (int i = 0; i < columns.length; i++) {
            columns[i] = vbs.get(i).getOid();
        }

        Integer defaultColSize = (Integer) ArgumentParser.getValue(settings, "Cc",
                0);
        if (defaultColSize == null) {
            defaultColSize = 16;
        }
        Integer maxLineLength = (Integer) ArgumentParser.getValue(settings, "Cw", 0);
        if (maxLineLength == null) {
            maxLineLength = 80;
        }
        TableFormatter tf = new TableFormatter(out,
                defaultColSize,
                maxLineLength, " ");
        if (settings.containsKey("Cf")) {
            String s = (String) ArgumentParser.getValue(settings, "Cf", 0);
            tf.setCompact(true);
            tf.setSeparator(s);
        }
        if (settings.containsKey("Cl")) {
            tf.setLeftAlign(true);
        }
        if (settings.containsKey("Cb")) {
            Integer bufferSize = (Integer) ArgumentParser.getValue(settings, "Cb", 0);
            if (bufferSize != null) {
                tf.setBufferSize(bufferSize);
            }
        }

        if (!settings.containsKey("Ch")) {

            long startTime = System.currentTimeMillis();
            synchronized (counter) {

                TableListener listener;
                if (operation == TABLE) {
                    listener = new TextTableListener(tf, settings.containsKey("Ci"));
                } else {
                    listener = new CVSTableListener(System.currentTimeMillis());
                }
                if (useDenseTableOperation) {
                    tableUtils.getDenseTable(target, columns, listener, counter,
                            lowerBoundIndex, upperBoundIndex);
                } else {
                    tableUtils.getTable(target, columns, listener, counter,
                            lowerBoundIndex, upperBoundIndex);
                }
                try {
                    counter.wait(timeout);
                } catch (InterruptedException ex) {
                }
            }
            tf.flush();
            err.println("Table received in " +
                    (System.currentTimeMillis() - startTime) +
                    " milliseconds.");
        } else {
            tf.flush();
        }
        snmp.close();
        return 0;
    }

    class CVSTableListener implements TableListener {

        private long requestTime;
        private boolean finished;

        public CVSTableListener(long time) {
            this.requestTime = time;
        }

        public boolean next(TableEvent event) {
            if (operation == TIME_BASED_CVS_TABLE) {
                out.print(requestTime);
                out.print(",");
            }
            out.print("\"" + event.getIndex() + "\",");
            for (int i = 0; i < event.getColumns().length; i++) {
                Variable v = event.getColumns()[i].getVariable();
                String value = v.toString();
                switch (v.getSyntax()) {
                    case SMIConstants.SYNTAX_IPADDRESS:
                    case SMIConstants.SYNTAX_OBJECT_IDENTIFIER:
                    case SMIConstants.SYNTAX_OPAQUE: {
                        out.print("\"");
                        out.print(value);
                        out.print("\"");
                        break;
                    }
                    case SMIConstants.SYNTAX_TIMETICKS: {
                        out.print(((AssignableFromLong) v).toLong());
                        break;
                    }
                    default: {
                        out.print(value);
                    }
                }
                if (i + 1 < event.getColumns().length) {
                    out.print(",");
                }
            }
            out.println();
            return true;
        }

        public void finished(TableEvent event) {
            synchronized (event.getUserObject()) {
                finished = true;
                event.getUserObject().notify();
            }
        }

        public boolean isFinished() {
            return finished;
        }

    }

    private void createSnapshot(List<?> snapshot) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(snapshotFile);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(snapshot);
            oos.flush();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException ex1) {
                }
            }
        }
    }

    private int dumpSnapshot() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(snapshotFile);
            ObjectInputStream ois = new ObjectInputStream(fis);
            List<?> l = (List<?>) ois.readObject();
            int i = 1;
            err.println("Dumping snapshot file '" + snapshotFile + "':");
            for (Iterator<?> it = l.iterator(); it.hasNext(); i++) {
                out.println("" + i + ": " + it.next());
            }
            out.println();
            err.println("Dumped " + l.size() + " variable bindings.");
            return 0;
        } catch (Exception ex) {
            ex.printStackTrace();
            return 1;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex1) {
                }
            }
        }
    }

    class TextTableListener implements TableListener {

        private boolean finished;
        private TableFormatter tf;
        boolean addIndex;

        public TextTableListener(TableFormatter tf, boolean addIndex) {
            this.tf = tf;
            this.addIndex = addIndex;
        }

        public void finished(TableEvent event) {
            tf.flush();
            out.flush();
            err.println();
            err.println("Table walk completed with status " + event.getStatus() +
                    ". Received " +
                    event.getUserObject() + " rows.");
            synchronized (event.getUserObject()) {
                finished = true;
                event.getUserObject().notify();
            }
        }

        public boolean next(TableEvent event) {
            int offset = addIndex ? 1 : 0;
            Object[] c = new Object[event.getColumns().length + offset];
            for (int i = 0; i < event.getColumns().length; i++) {
                c[i] = event.getColumns()[i + offset];
            }
            tf.addRow(c);
            ((Counter32) event.getUserObject()).increment();
            return true;
        }

        public boolean isFinished() {
            return finished;
        }
    }

    private PDU walk(Snmp snmp, PDU request, Target<?> target, final List<VariableBinding> snapshot) throws
            IOException {
        try {
            request.setNonRepeaters(0);
        } catch (UnsupportedOperationException uex) {
            // ignore
        }
        OID rootOID = request.get(0).getOid();
        PDU response = null;
        final WalkCounts counts = new WalkCounts();
        final long startTime = System.currentTimeMillis();
        TreeUtils treeUtils = new TreeUtils(snmp, pduFactory);
        if (settings.containsKey("ilo")) {
            treeUtils.setIgnoreLexicographicOrder(true);
        }
        TreeListener treeListener = new TreeListener() {
            private boolean finished = false;

            public boolean next(TreeEvent e) {
                counts.requests++;
                if (e.getVariableBindings() != null) {
                    VariableBinding[] vbs = e.getVariableBindings();
                    counts.objects += vbs.length;
                    for (VariableBinding vb : vbs) {
                        if (snapshot != null) {
                            snapshot.add(vb);
                        }
                        out.println(vb.toString());
                    }
                }
                return true;
            }

            public void finished(TreeEvent e) {
                if ((e.getVariableBindings() != null) &&
                        (e.getVariableBindings().length > 0)) {
                    next(e);
                }
                err.println();
                err.println("Total requests sent:    " + counts.requests);
                err.println("Total objects received: " + counts.objects);
                err.println("Total walk time:        " +
                        (System.currentTimeMillis() - startTime) +
                        " milliseconds");
                if (e.isError()) {
                    err.println("The following error occurred during walk:");
                    err.println(e.getErrorMessage());
                    //e.getException().printStackTrace();
                }
                finished = true;
                synchronized (this) {
                    this.notify();
                }
            }

            public boolean isFinished() {
                return finished;
            }
        };
        synchronized (treeListener) {
            treeUtils.getSubtree(target, rootOID, null, treeListener);
            try {
                treeListener.wait();
            } catch (InterruptedException ex) {
                err.println("Tree retrieval interrupted: " + ex.getMessage());
            }
        }
        return response;
    }

    private static List<VariableBinding> getVariableBindings(String[] args, int position) {
        ArrayList<VariableBinding> v = new ArrayList<>(args.length - position + 1);
        for (int i = position; i < args.length; i++) {
            String oid = args[i];
            char type = 'i';
            String value = null;
            int equal = oid.indexOf("={");
            if (equal > 0) {
                oid = args[i].substring(0, equal);
                type = args[i].charAt(equal + 2);
                value = args[i].substring(args[i].indexOf('}') + 1);
            } else if (oid.indexOf('-') > 0) {
                StringTokenizer st = new StringTokenizer(oid, "-");
                if (st.countTokens() != 2) {
                    throw new IllegalArgumentException("Illegal OID range specified: '" +
                            oid);
                }
                oid = st.nextToken();
                VariableBinding vbLower = new VariableBinding(new OID(oid));
                v.add(vbLower);
                long last = Long.parseLong(st.nextToken());
                long first = vbLower.getOid().lastUnsigned();
                for (long k = first + 1; k <= last; k++) {
                    OID nextOID = new OID(vbLower.getOid().getValue(), 0,
                            vbLower.getOid().size() - 1);
                    nextOID.appendUnsigned(k);
                    VariableBinding next = new VariableBinding(nextOID);
                    v.add(next);
                }
                continue;
            }
            VariableBinding vb = new VariableBinding(new OID(oid));
            if (value != null) {
                Variable variable;
                switch (type) {
                    case 'i':
                        variable = new Integer32(Integer.parseInt(value));
                        break;
                    case 'u':
                        variable = new UnsignedInteger32(Long.parseLong(value));
                        break;
                    case 's':
                        variable = new OctetString(value);
                        break;
                    case 'x':
                        variable = OctetString.fromString(value, ':', 16);
                        break;
                    case 'd':
                        variable = OctetString.fromString(value, '.', 10);
                        break;
                    case 'b':
                        variable = OctetString.fromString(value, ' ', 2);
                        break;
                    case 'n':
                        variable = new Null();
                        break;
                    case 'o':
                        variable = new OID(value);
                        break;
                    case 't':
                        variable = new TimeTicks(Long.parseLong(value));
                        break;
                    case 'a':
                        variable = new IpAddress(value);
                        break;
                    default:
                        throw new IllegalArgumentException("Variable type " + type +
                                " not supported");
                }
                vb.setVariable(variable);
            }
            v.add(vb);
        }
        return v;
    }

    private static Address getAddress(String transportAddress) {
        String transport = "udp";
        int colon = transportAddress.indexOf(':');
        if (colon > 0) {
            transport = transportAddress.substring(0, colon);
            transportAddress = transportAddress.substring(colon + 1);
        }
        // set default port
        if (transportAddress.indexOf('/') < 0) {
            transportAddress += "/161";
        }
        if (transport.equalsIgnoreCase("udp")) {
            return new UdpAddress(transportAddress);
        } else if (transport.equalsIgnoreCase("tcp")) {
            return new TcpAddress(transportAddress);
        }
        throw new IllegalArgumentException("Unknown transport " + transport);
    }

    public synchronized int listen() throws IOException {
        AbstractTransportMapping<? extends Address> transport;
        Address address = target.getAddress();
        if (address instanceof TcpAddress) {
            transport = new DefaultTcpTransportMapping((TcpAddress) address);
        } else {
            transport = new DefaultUdpTransportMapping((UdpAddress) address);
        }
        ThreadPool threadPool =
                ThreadPool.create("DispatcherPool", numDispatcherThreads);
        MessageDispatcher mtDispatcher =
                new MultiThreadedMessageDispatcher(threadPool,
                        new SnmpCommandMessageDispatcher());

        // add message processing models
        mtDispatcher.addMessageProcessingModel(new MPv1());
        mtDispatcher.addMessageProcessingModel(new MPv2c());
        mtDispatcher.addMessageProcessingModel(new MPv3(localEngineID.getValue()));

        // add all security protocols
        SecurityProtocols.getInstance().addDefaultProtocols();
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        Snmp snmp = new Snmp(mtDispatcher, transport);
        if (version == SnmpConstants.version3) {
            USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            if (authoritativeEngineID != null) {
                snmp.setLocalEngine(authoritativeEngineID.getValue(), 0, 0);
            }
            SnmpConfigurator snmpConfig = new SnmpConfigurator();
            snmpConfig.configure(snmp, settings);
        } else {
            CommunityTarget<?> target = new CommunityTarget<>(address, community);
            this.target = target;
        }

        snmp.addCommandResponder(this);

        transport.listen();
        out.println("Listening on " + address);

        try {
            this.wait();
        } catch (InterruptedException ex) {
        }
        return 0;
    }

    public static void main(String[] args) {
        Map<String, List<Object>> commandLineParameters = null;
        try {
            String[] commandSet =
                    ArgumentParser.selectCommand(args, ALL_OPTIONS, COMMANDS);
            if (commandSet == null) {
                printUsage();
                System.exit(2);
            }
            ArgumentParser parser =
                    new ArgumentParser(commandSet[1], commandSet[2]);
            commandLineParameters = parser.parse(args);
            String command =
                    (String) ArgumentParser.getValue(commandLineParameters, "command", 0);
            if (commandLineParameters.containsKey("w")) {
                // set console width
                Integer width =
                        (Integer) ArgumentParser.getValue(commandLineParameters, "w", 0);
                if (width > 20) {
                    stdoutWidth = width;
                }
            }
            if (commandLineParameters.containsKey("s")) {
                silent = true;
            }
            if (commandLineParameters.containsKey("d")) {
                LogLevel level =
                        new LogLevel(((String) ArgumentParser.getValue(commandLineParameters, "d", 0)).toUpperCase());
                LogFactory.getLogFactory().getRootLogger().setLogLevel(level);
            }
            if ("help".equals(command)) {
                String helpCmd =
                        (String) ArgumentParser.getValue(commandLineParameters, "subject", 0);
                SnmpCommand b = new SnmpCommand(command, commandLineParameters);
                String help = b.help("", helpCmd, true, true);
                out.println(help);
                //printUsage();
                System.exit(0);
            } else if ("example".equals(command)) {
                String helpCmd =
                        (String) ArgumentParser.getValue(commandLineParameters, "subject", 0);
                SnmpCommand b = new SnmpCommand(command, commandLineParameters);
                String help = b.example("", helpCmd);
                out.println(help);
                //printUsage();
                System.exit(0);
            } else if ("version".equals(command)) {
                printVersion();
                System.exit(0);
            } else {
                SnmpCommand browser = new SnmpCommand(command, commandLineParameters);
                browser.run();
                System.exit(browser.returnCode);
            }
        } catch (ArgumentParseException apex) {
            if (args.length == 0 || "help".equals(args[0])) {
                try {
                    printUsage();
                } catch (IOException ex1) {
                    ex1.printStackTrace();
                }
            } else {
                System.out.println(apex.getMessage());
            }
        } catch (NullPointerException npe) {
            npe.printStackTrace();
        } catch (RuntimeException rex) {
            System.out.println(rex.getMessage());
            if (commandLineParameters != null && commandLineParameters.containsKey("d") &&
                    "debug".equalsIgnoreCase(
                            (String) ArgumentParser.getValue(commandLineParameters, "d", 0))) {
                rex.printStackTrace();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        System.exit(1);
    }


    public void run() {
        try {
            switch (operation) {
                case SNAPSHOT_DUMP: {
                    returnCode = dumpSnapshot();
                    break;
                }
                case LISTEN: {
                    returnCode = listen();
                    break;
                }
                case TABLE:
                case CVS_TABLE:
                case TIME_BASED_CVS_TABLE: {
                    returnCode = table();
                    break;
                }
                default: {
                    PDU response = send();
                    if ((pduType == PDU.TRAP) ||
                            (pduType == PDU.REPORT) ||
                            (pduType == PDU.V1TRAP) ||
                            (pduType == PDU.RESPONSE)) {
                        out.println(PDU.getTypeString(pduType) +
                                " sent successfully");
                    } else if (response == null) {
                        if (operation != WALK) {
                            out.println("Request timed out.");
                        }
                    } else if (response.getType() == PDU.REPORT) {
                        printReport(response);
                    } else if (operation == DEFAULT) {
                        err.println("Response received with requestID=" +
                                response.getRequestID() +
                                ", errorIndex=" +
                                response.getErrorIndex() + ", " +
                                "errorStatus=" + response.getErrorStatusText() +
                                "(" + response.getErrorStatus() + ")");
                        printVariableBindings(response);
                    } else {
                        err.println("Received something strange: requestID=" +
                                response.getRequestID() +
                                ", errorIndex=" +
                                response.getErrorIndex() + ", " +
                                "errorStatus=" + response.getErrorStatusText() +
                                "(" + response.getErrorStatus() + ")");
                        printVariableBindings(response);
                    }
                }
            }
        } catch (MessageException mex) {
            out.println(mex.getMessage());
            returnCode = 1;
        } catch (IOException iox) {
            iox.printStackTrace();
            returnCode = 1;
        } catch (NullPointerException npe) {
            npe.printStackTrace();
        }
    }


    private byte[] getUserEngineID() {
        byte[] engineID;
        OctetString ne =
                SnmpConfigurator.createOctetString((String)
                                ArgumentParser.getValue(settings, "CE", 0),
                        null);
        if (ne == null) {
            engineID = ((UserTarget) target).getAuthoritativeEngineID();
        } else {
            engineID = ne.getValue();
        }
        if ((engineID == null) || (engineID.length == 0)) {
            engineID = snmp.discoverAuthoritativeEngineID(target.getAddress(), target.getTimeout());
        }
        return engineID;
    }


    protected static void printVersion() {
        out.println();
        out.println("SnmpCommand " + VersionInfo.getVersion() + " [SNMP4J " +
                VersionInfo.getVersion() + "]");
        out.println("Copyright " + (char) 0xA9 + " 2004-2018, Frank Fock");
        out.println("http://www.snmp4j.org");
        out.println();
    }

    public static void printUsage() throws IOException {
        SnmpCommand b = new SnmpCommand("help", new HashMap<String, List<Object>>());
        String help = b.help("", null, true, false);
        out.println(help);
    }

    public <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport, A incomingAddress,
                                                   ByteBuffer wholeMessage, TransportStateReference tmStateReference) {
        byte[] msg = new byte[wholeMessage.remaining()];
        wholeMessage.get(msg);
        wholeMessage.rewind();
        out.println("Packet received from " + incomingAddress +
                " on " + sourceTransport.getListenAddress() + ":");
        out.println(new OctetString(msg).toHexString());
    }

    public void processMessage(TransportMapping<?> sourceTransport,
                               Address destAddress, byte[] message) {
        out.println("Packet sent to " + destAddress +
                " on " + sourceTransport.getListenAddress() + ":");
        out.println(new OctetString(message).toHexString());
    }


    class WalkCounts {
        public int requests;
        public int objects;
    }

    static class FilterPrintStream extends PrintStream {

        public FilterPrintStream(OutputStream out) {
            super(out);
        }

        public void print(Object obj) {
            if (!silent) {
                super.print(obj);
            }
        }

        public void print(String s) {
            if (!silent) {
                super.print(s);
            }
        }

        public void println() {
            if (!silent) {
                super.println();
            }
        }

        public void println(Object x) {
            if (!silent) {
                super.println(x);
            }
        }

        public void println(String x) {
            if (!silent) {
                super.println(x);
            }
        }
    }

    public class SnmpCommandMessageDispatcher extends MessageDispatcherImpl {

        public SnmpCommandMessageDispatcher() {
            super();
        }

        @Override
        public <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport,
                                                       A incomingAddress, ByteBuffer wholeMessage,
                                                       TransportStateReference tmStateReference) {
            if (packetDumpEnabled) {
                SnmpCommand.this.processMessage(sourceTransport, incomingAddress,
                        wholeMessage, tmStateReference);
            }
            super.processMessage(sourceTransport, incomingAddress, wholeMessage,
                    tmStateReference);
        }

        @Override
        protected <A extends Address> void sendMessage(TransportMapping<? super A> transport, A destAddress,
                                   byte[] message,
                                   TransportStateReference tmStateReference,
                                   long timeoutMillis, int maxRetries) throws IOException {
            super.sendMessage(transport, destAddress, message, tmStateReference, timeoutMillis, maxRetries);
            if (packetDumpEnabled) {
                SnmpCommand.this.processMessage(transport, destAddress, message);
            }
        }

    }

}
