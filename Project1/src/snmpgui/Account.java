package snmpgui;

public class Account {
    private String name;
    private String ipAddress;
    private String community;
    private String port;

    // Default constructor
    public Account() {
    }

    // Constructor with parameters
    public Account(String name, String ipAddress, String community, String port) {
        this.name = name;
        this.ipAddress = ipAddress;
        this.community = community;
        this.port = port;
    }

    // Getter and setter methods for the fields
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }
}

