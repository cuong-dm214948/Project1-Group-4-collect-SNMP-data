package snmpgui;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.stage.Stage;
import javafx.scene.layout.VBox;

public class OtherClass extends Application {

    @Override
    public void start(Stage primaryStage) {
        TabPane tabPane = new TabPane();
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        // Create the first tab
        Tab tab1 = new Tab("Snmp Browser");
        Tab tab2 = new Tab("Snmp Traps");

        // Create an instance of MIBTreeGUI

        NodeInfo node = new NodeInfo();

        // Create a VBox to hold the content of the tab
        VBox tab1Content = new VBox();
        VBox tab2Content = new VBox();

        // Initialize the GUI and pass the VBox as a parameter

        node.initializeTrap(tab2Content);

        // Set the VBox as the content of the tab
        tab1.setContent(tab1Content);
        tab2.setContent(tab2Content);

        // Add the tab to the tabPane
        tabPane.getTabs().add(tab1);
        tabPane.getTabs().add(tab2);

        // Create additional tabs if needed...
        // Tab tab2 = new Tab("Tab 2");
        // ...

        Scene scene = new Scene(tabPane,840,630);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}










