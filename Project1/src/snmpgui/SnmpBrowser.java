package snmpgui;

import java.io.File;
import java.util.List;

import javafx.scene.control.MenuItem;
import java.io.IOException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.MenuButton;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.scene.control.TextField;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.scene.control.TextArea;


public class SnmpBrowser extends Application {
	
    private TextField textField1;
    private TextField textField2;
    private TextField textField3;
    private TextField textField5;
    private TextField textField6;
    private TextField textField7;
    private TextField textField8;
    private TextField textField9;
    private TextArea textField11;
    private JsonNode jsonRoot1;
    private JsonNode jsonRoot2;
    private JsonNode jsonRoot3;
    private MenuButton menuButton;
	
    private static final String FILE_NAME = "Account.json";
	private static final String JSON_FILE_PATH1 = "SNMPv2-MIB.json";
	private static final String JSON_FILE_PATH2 = "HOST-RESOURCES-MIB.json";
	private static final String JSON_FILE_PATH3 = "IF-MIB.json";
	
	private String ipAddress1;
	private String community1;
	
	@Override
	public void start(Stage stage) { 
        menuButton = new MenuButton("   Host   ");

        // Read the accounts from the JSON file
        List<Account> accountList = readAccountsFromFile();
        // ...
    	
        for (Account account : accountList) {
            MenuItem menuItem = new MenuItem(account.getName());
            menuButton.getItems().add(menuItem);

            final MenuItem finalMenuItem = menuItem; // Create a final copy of menuItem

            menuItem.setOnAction(event -> {
                menuButton.setText(finalMenuItem.getText());
                ipAddress1 = account.getIpAddress();
                community1 = account.getCommunity();               
            });
        }       
		
        TreeView<String> treeView = new TreeView<>();
        treeView.setPrefSize(400, 200);//width, height
        
        try {
        	// Create the ObjectMapper
        	ObjectMapper objectMapper = new ObjectMapper();

        	// Read the JSON files and obtain the root nodes for each file
        	jsonRoot1 = objectMapper.readTree(new File(JSON_FILE_PATH1));
        	jsonRoot2 = objectMapper.readTree(new File(JSON_FILE_PATH2));
        	jsonRoot3 = objectMapper.readTree(new File(JSON_FILE_PATH3));

        	// Create the common root item
        	TreeItem<String> root = new TreeItem<>("MIB Tree");

        	// Create the branch items
        	TreeItem<String> rootNode1 = new TreeItem<>("SNMPv2-MIB");
        	TreeItem<String> rootNode2 = new TreeItem<>("HOST RESOURCE-MIB");
        	TreeItem<String> rootNode3 = new TreeItem<>("IF-MIB");

        	// Build the tree structure for each branch
        	createTreeItem(jsonRoot1, rootNode1);
        	createTreeItem(jsonRoot2, rootNode2);
        	createTreeItem(jsonRoot3, rootNode3);

        	// Add the branch items to the common root item
        	root.getChildren().addAll(rootNode1, rootNode2, rootNode3);
        	treeView.setRoot(root);
        } catch (IOException e) {
//            e.printStackTrace();
        	e.getMessage();
        }
        
        treeView.setOnMouseClicked(event -> {
            TreeItem<String> selectedItem = treeView.getSelectionModel().getSelectedItem();
            handleTreeItemClick(selectedItem, jsonRoot1);
            handleTreeItemClick(selectedItem, jsonRoot2);
            handleTreeItemClick(selectedItem, jsonRoot3);
        });
		//creating label and Text Field
		Text text1 = new Text("Name:");
		textField1 = new TextField();
		
		Text text2 = new Text("Oid:");
		textField2 = new TextField();
		
		Text text3 = new Text("Composed Type:");
		textField3 = new TextField();
		
		Text text5 = new Text("Status:");
		textField5 = new TextField();
		
		Text text6 = new Text("Access:");
		textField6 = new TextField();
		
		Text text7 = new Text("Kind:");
		textField7 = new TextField();
		
		Text text8 = new Text("SMI type:");
		textField8 = new TextField();
		
		Text text9 = new Text("Size:");
		textField9 = new TextField();
		
		Text text11 = new Text("Description:");
		textField11 = new TextArea();
		textField11.setWrapText(true); 
		textField11.setPrefColumnCount(31); // Set the preferred number of columns
		textField11.setPrefRowCount(9);
		
		//Creating a Grid Pane
		GridPane gridPane = new GridPane();
		gridPane.setPrefSize(100,380);//width, height
		gridPane.setPadding(new Insets(5, 5, 5, 5));
		gridPane.setVgap(5);
		gridPane.setHgap(5);
		gridPane.setAlignment(Pos.TOP_LEFT);
		
		//Arranging all the nodes in the grid
		gridPane.add(text1, 0, 0);
		gridPane.add(textField1, 1, 0);
		gridPane.add(text2, 0, 1);
		gridPane.add(textField2, 1, 1);
		gridPane.add(text3, 0, 2);
		gridPane.add(textField3, 1, 2);
		gridPane.add(text5, 0, 3);
		gridPane.add(textField5, 1, 3);
		gridPane.add(text6, 0, 4);
		gridPane.add(textField6, 1, 4);
		gridPane.add(text7, 0, 5);
		gridPane.add(textField7, 1, 5);
		gridPane.add(text8, 0, 6);
		gridPane.add(textField8, 1, 6);
		gridPane.add(text9, 0, 7);
		gridPane.add(textField9, 1, 7);
		gridPane.add(text11, 0, 8);
		gridPane.add(textField11, 1, 8);
		
		//Styling nodes		
		text1.setStyle("-fx-font: normal bold 14px 'serif' ");
		textField1.setStyle("-fx-font: normal bold 12px 'serif' ");
		text2.setStyle("-fx-font: normal bold 12px 'serif' ");
		text3.setStyle("-fx-font: normal bold 12px 'serif' ");
		text5.setStyle("-fx-font: normal bold 12px 'serif' ");
		text6.setStyle("-fx-font: normal bold 12px 'serif' ");
		text7.setStyle("-fx-font: normal bold 12px 'serif' ");
		text8.setStyle("-fx-font: normal bold 12px 'serif' ");
		text9.setStyle("-fx-font: normal bold 12px 'serif' ");
		text11.setStyle("-fx-font: normal bold 12px 'serif' ");
		gridPane.setStyle("-fx-background-color: BEIGE;");
		
		//creating getconnection
		GridPane gridPane1 = new GridPane();
		gridPane1.setStyle("-fx-background-color: BEIGE;");
		gridPane1.setPrefSize(400, 100);	
		gridPane1.setPadding(new Insets(5, 5, 5, 5));	
		//Setting the vertical and horizontal gaps between the columns
		gridPane1.setVgap(5);
		gridPane1.setHgap(5);
		
		//Setting the Grid alignment
		gridPane1.setAlignment(Pos.TOP_RIGHT);
		Text text12 = new Text("Query result:");
		TextArea textField12 = new TextArea();
		textField12.setPrefRowCount(32);
		
		gridPane1.add(text12, 0, 0);
		gridPane1.add(textField12, 0, 1);
			
		//Creating Buttons
		Button button1 = new Button("    Get    ");
		Button button2 = new Button("  GetNext  ");
		Button button3 = new Button("    Walk   ");
		button1.setStyle("-fx-background-color: darkslateblue; -fx-text-fill: white;");
		button2.setStyle("-fx-background-color: darkslateblue; -fx-text-fill: white;");
		button3.setStyle("-fx-background-color: darkslateblue; -fx-text-fill: white;");
		HBox hbox = new HBox(100,button1,button2,button3);
//		hbox.setPadding(new Insets(0));
	    hbox.setAlignment(Pos.TOP_CENTER);	    
	    hbox.setStyle("-fx-background-color: BEIGE;");
	    
	    GridPane gridPane2 = new GridPane();
		gridPane2.setStyle("-fx-background-color: BEIGE;");	
		gridPane2.setPadding(new Insets(5, 5, 5, 5));	
		//Setting the vertical and horizontal gaps between the columns
		gridPane2.setVgap(5);
		gridPane2.setHgap(5);
		
		//Setting the Grid alignment
		gridPane2.setAlignment(Pos.TOP_LEFT);
		gridPane2.add(treeView, 0, 1);
		gridPane2.add(gridPane, 0, 2);
		
	    GridPane gridPane3 = new GridPane();
		gridPane3.setStyle("-fx-background-color: BEIGE;");
		gridPane1.setPrefSize(400, 600);	
		gridPane3.setPadding(new Insets(5, 5, 5, 5));	
		//Setting the vertical and horizontal gaps between the columns
		gridPane3.setVgap(5);
		gridPane3.setHgap(5);
		
		//Setting the Grid alignment
		gridPane3.setAlignment(Pos.TOP_LEFT);
		gridPane3.add(menuButton, 0, 0);
		gridPane3.add(hbox, 1, 0);		
		gridPane3.add(gridPane2, 0, 1);
		gridPane3.add(gridPane1, 1, 1);
		
		gridPane3.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
				button1.setOnAction(event -> {
				    String oid = textField2.getText() + ".0";
				    String result = snmpget.SnmpGet.snmpGet(ipAddress1,community1,oid);
				    textField12.setText(result);
				});
			}});
			
		gridPane3.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
				button2.setOnAction(event -> {
				    String oid = textField2.getText() + ".0";
				    String result = snmpgetnext.SnmpGetNext.snmpGetNext(ipAddress1,community1,oid);
				    textField12.setText(result);
				});
			}});
			
		gridPane3.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
				button3.setOnAction(event -> {
				    String oid = textField2.getText();
				    String result = snmpwalk.SnmpWalk.snmpWalk(ipAddress1,community1,oid);
				    textField12.setText(result);
				});
			}});
				
		BorderPane root = new BorderPane();
	    root.setTop(gridPane3);
		Scene scene1 = new Scene(root,840,630);//width,height
		stage.setTitle("Snmp");
		stage.setScene(scene1);
		stage.show();
	}
	
	private void createTreeItem(JsonNode jsonNode, TreeItem<String> parentItem) {
	    // Iterate over the fields or elements of the JSON node
	    jsonNode.fields().forEachRemaining(entry -> {
	        JsonNode childNode = entry.getValue();
	        // Create a TreeItem with the name as the label
	        TreeItem<String> childItem = new TreeItem<>();
	        childItem.setValue(entry.getKey());
	        parentItem.getChildren().add(childItem);

	        // Recursively build the tree structure for child nodes
	        createTreeItem(childNode, childItem);
	    });
	}
    
    private void handleTreeItemClick(TreeItem<String> selectedItem,JsonNode jsonRoot) {
        if (selectedItem != null) {
           if (selectedItem.getParent() != null ) {
                JsonNode selectedNode = findNodeByPath(selectedItem.getValue(),jsonRoot);

                if (selectedNode != null) {
                    String text1 = selectedNode.get("name").asText();
                    String text2 = selectedNode.get("oid").asText();
                    
                    JsonNode nodeNode = selectedNode.get("nodetype");
                    if (nodeNode != null) {
                        String text3 = nodeNode.asText();
                        textField7.setText(text3);
                    }
                    
                    JsonNode maxAccessNode = selectedNode.get("maxaccess");                 
                    if (maxAccessNode != null) {
                    	String text6 = maxAccessNode.asText();
                    	textField6.setText(text6); 
                    }
                    
                    JsonNode statusNode = selectedNode.get("status");
                    if (statusNode != null ) {
                    	String text7 = statusNode.asText();
                    	textField5.setText(text7);
                    }
                    
                    JsonNode descriptionNode = selectedNode.get("description");
                    if (descriptionNode != null) {
                    	String text8 = descriptionNode.asText();
                    	textField11.setText(text8);
                    }
                    String text4 = selectedNode.get("class").asText();
                    
                    JsonNode syntaxNode = selectedNode.get("syntax");
                    if (syntaxNode != null && syntaxNode.has("constraints") && syntaxNode.has("type")) {
                        JsonNode constraintsNode = syntaxNode.get("constraints");
                        String text5 = syntaxNode.get("type").asText();
                        textField3.setText(text5);
                        if (constraintsNode != null && constraintsNode.has("size")) {
                            JsonNode sizeNode = constraintsNode.get("size");
                            if (sizeNode.isArray() && sizeNode.size() > 0) {
                                JsonNode minNode = sizeNode.get(0).get("min");
                                JsonNode maxNode = sizeNode.get(0).get("max");
                                if (minNode != null && maxNode != null) {
                                	String text9 = minNode.asText();
                                    String text10 = maxNode.asText();
                                    textField9.setText(text9 + " .. " + text10);
                                }
                            }
                        }
                    }                 
                    
                    textField1.setText(text1);
                    textField2.setText(text2);
                    textField8.setText(text4);
                }
            }
        }
    }

    private JsonNode findNodeByPath(String path,JsonNode jsonRoot) {
        String[] parts = path.split("\\.");

        JsonNode currentNode = jsonRoot;
        for (String part : parts) {
            if (currentNode.has(part)) {
                currentNode = currentNode.get(part);
            } else {
                return null;
            }
        }
        return currentNode;
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
    
    
	public static void main(String args[]){
	launch(args);
	}	
}

