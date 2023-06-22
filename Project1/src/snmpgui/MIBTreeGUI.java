package snmpgui;

import snmptraps.TestSnmpTrap;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class MIBTreeGUI extends Application {

    private TestSnmpTrap trapSender;

    @Override
    public void start(Stage primaryStage) {
        trapSender = new TestSnmpTrap();

        Button sendTrapButton = new Button("Send Trap");
        sendTrapButton.setOnAction(event -> {
            String trapReceiverAddress = "192.168.56.1";
            trapSender.sendSNMPTrap(trapReceiverAddress);
        });

        VBox root = new VBox(sendTrapButton);
        Scene scene = new Scene(root, 300, 200);

        primaryStage.setTitle("SNMP Trap GUI");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}






