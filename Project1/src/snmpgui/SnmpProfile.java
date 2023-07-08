package snmpgui;

import java.io.File;
import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class SnmpProfile extends Application {

    private Stage profileWindow;
    private static final String FILE_NAME = "Account.json";

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        MenuButton menuButton = new MenuButton("   Host   ");

        // Read the accounts from the JSON file
        List<Account> accountList = readAccountsFromFile();

        // Create menu items for each account
        for (Account account : accountList) {
        	MenuItem menuItem = new MenuItem(account.getName());
            menuButton.getItems().add(menuItem);
            menuItem.setOnAction(event -> {
                // Display the info for the selected menu item
            MIB nodeInfo = new SnmpBrowser();
                Stage stage1 = new Stage();
                nodeInfo.start(stage1);
                stage.close();
            });
        }

        // Add event listener to item1
        item1.setOnAction(event -> showProfilesWindow());

        VBox root = new VBox(menuButton);
        Scene scene = new Scene(root, 300, 200);

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void showProfilesWindow() {
        if (profileWindow == null) {
            profileWindow = new Stage();
            profileWindow.setTitle("Profile Details");
            profileWindow.setOnCloseRequest(event -> profileWindow = null);

            VBox root = new VBox();
            Label nameLabel = new Label("Name: " + name);
            Label ipLabel = new Label("IP: " + ipAddress);
            Label communityLabel = new Label("Community: " + community);
            Label portLabel = new Label("Port: " + port);
            root.getChildren().addAll(nameLabel, ipLabel, communityLabel, portLabel);

            Scene scene = new Scene(root, 300, 200);
            profileWindow.setScene(scene);
        }

        profileWindow.show();
    }
    
    private List<Account> readAccountsFromFile() {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            File file = new File(FILE_NAME);
            if (file.exists()) {
                return objectMapper.readValue(file, new TypeReference<List<Account>>() {});
            }
        } catch (IOException e) {
            System.out.println("Error reading from file: " + e.getMessage());
        }
        return List.of(); // Return an empty list if file doesn't exist or there's an error
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
}


