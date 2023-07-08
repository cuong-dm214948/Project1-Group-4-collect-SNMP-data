package snmpgui;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SnmpAgent extends Application {
    private TextField textField1;
    private TextField textField2;
    private TextField textField3;
    private TextField textField4;

    private static final String FILE_NAME = "Account.json";
    
    private String name;
    private String ipAddress;
    private String community;
    private String port;

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
        readAccountsFromFile();

        root.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent arg0) {
                button1.setOnAction(event -> {
                    name = textField1.getText();
                    ipAddress = textField2.getText();
                    community = textField3.getText();
                    port = textField4.getText();

                    // Store data to file
                    storeDataToFile(name, ipAddress, community, port);

                    SnmpBrowser nodeInfo = new SnmpBrowser();
                    Stage stage1 = new Stage();
                    nodeInfo.start(stage1);
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
    	try {
    	    ObjectMapper objectMapper = new ObjectMapper();

    	    // Read existing accounts from the file
    	    List<Account> accountList;

    	    // Check if the file exists
    	    File file = new File(FILE_NAME);
    	    if (file.exists()) {
    	        // If the file exists, read the existing accounts from it
    	        accountList = objectMapper.readValue(file, new TypeReference<List<Account>>() {});

    	        // Check if the new account's ipAddress already exists in the file
    	        boolean ipAddressExists = accountList.stream()
    	                .anyMatch(account -> account.getIpAddress().equals(ipAddress));

    	        if (ipAddressExists) {
    	            System.out.println("The account with the specified ipAddress already exists. " +
    	                    "Skipping adding the new account.");
    	            return; // Skip adding the new account
    	        }
    	    } else {
    	        // If the file does not exist, create a new list
    	        accountList = new ArrayList<>();
    	    }

    	    // Add the new account
    	    Account account = new Account(name, ipAddress, community, port);
    	    accountList.add(account);

    	    // Write the updated account list to the file
    	    objectMapper.writeValue(file, accountList);
    	} catch (IOException e) {
    	    System.out.println("Error writing to file: " + e.getMessage());
    	}

    }

    private void readAccountsFromFile() {
        try {
            ObjectMapper objectMapper = new ObjectMapper();

            File file = new File(FILE_NAME);
            if (file.exists()) {
                // Read the existing account list from the file
                List<Account> accountList = objectMapper.readValue(file, new TypeReference<List<Account>>() {});
                
                if (!accountList.isEmpty()) {
                    Account firstAccount = accountList.get(0);
                    textField1.setText(firstAccount.getName());
                    textField2.setText(firstAccount.getIpAddress());
                    textField3.setText(firstAccount.getCommunity());
                    textField4.setText(firstAccount.getPort());
                }
            }
            
        } catch (IOException e) {
           System.out.println("Error reading from file: " + e.getMessage());
        }
//        return new ArrayList<>();
    }

    public static void main(String args[]) {
        launch(args);
    }
}



