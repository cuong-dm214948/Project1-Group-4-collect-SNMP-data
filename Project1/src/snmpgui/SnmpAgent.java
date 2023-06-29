package snmpgui;
import java.io.*;
import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.stage.Stage;

public class SnmpAgent extends Application {
    private TextField textField1;
    private TextField textField2;
    private TextField textField3;
    private TextField textField4;

    private static final String FILE_NAME = "snmp_agent_info.txt";

    @Override
    public void start(Stage stage) {
        // Creating label and Text Field
        Text text1 = new Text("Name:");
        textField1 = new TextField();

        Text text2 = new Text("Ip address:");
        textField2 = new TextField();

        Text text3 = new Text("Community:");
        textField3 = new TextField();

        Text text4 = new Text("Port:");
        textField4 = new TextField();

        // Creating a Grid Pane
        GridPane gridPane = new GridPane();

        // Setting the padding
        gridPane.setPadding(new Insets(5, 5, 5, 5));

        // Setting the vertical and horizontal gaps between the columns
        gridPane.setVgap(5);
        gridPane.setHgap(5);

        // Setting the Grid alignment
        gridPane.setAlignment(Pos.CENTER);

        // Arranging all the nodes in the grid
        gridPane.add(text1, 0, 0);
        gridPane.add(textField1, 1, 0);
        gridPane.add(text2, 0, 1);
        gridPane.add(textField2, 1, 1);
        gridPane.add(text3, 0, 2);
        gridPane.add(textField3, 1, 2);
        gridPane.add(text4, 0, 3);
        gridPane.add(textField4, 1, 3);

        // Styling nodes
        text1.setStyle("-fx-font: normal bold 20px 'serif' ");
        text2.setStyle("-fx-font: normal bold 20px 'serif' ");
        text3.setStyle("-fx-font: normal bold 20px 'serif' ");
        text4.setStyle("-fx-font: normal bold 20px 'serif' ");

        Button button1 = new Button("     OK     ");
        HBox hbox = new HBox(button1);
        hbox.setPadding(new Insets(10));
        hbox.setAlignment(Pos.TOP_CENTER);

        BorderPane root = new BorderPane();
        root.setTop(gridPane);
        root.setCenter(hbox);

        // Read data from file if it exists
        readDataFromFile();

        gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent arg0) {
                button1.setOnAction(event -> {
                    String name = textField1.getText();
                    String ipAddress = textField2.getText();
                    String community = textField3.getText();
                    String port = textField4.getText();

                    // Store data to file
                    storeDataToFile(name, ipAddress, community, port);

                    SnmpBrowser nodeInfo = new SnmpBrowser(name, ipAddress, community, port);
                    Stage nodeInfoStage = new Stage();
                    nodeInfo.start(nodeInfoStage);
                    stage.close();
                });
            }
        });

        // Creating a scene object
        Scene scene = new Scene(root, 350, 170);

        // Setting title to the Stage
        stage.setTitle("Snmp Agent");

        // Adding scene to the stage
        stage.setScene(scene);

        // Displaying the contents of the stage
        stage.show();
    }

    private void storeDataToFile(String name, String ipAddress, String community, String port) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME))) {
            writer.write(name);
            writer.newLine();
            writer.write(ipAddress);
            writer.newLine();
            writer.write(community);
            writer.newLine();
            writer.write(port);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
        }
    }

    private void readDataFromFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader(FILE_NAME))) {
            String name = reader.readLine();
            String ipAddress = reader.readLine();
            String community = reader.readLine();
            String port = reader.readLine();

            if (name != null && ipAddress != null && community != null && port != null) {
                textField1.setText(name);
                textField2.setText(ipAddress);
                textField3.setText(community);
                textField4.setText(port);
            }
        } catch (IOException e) {
            System.out.println("Error reading from file: " + e.getMessage());
        }
    }

    public static void main(String args[]) {
        launch(args);
    }
}
