package snmpgui;

import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import java.io.File;
import java.io.IOException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.scene.control.TextField;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.scene.control.TextArea;

public class MIBTreeExample extends Application {
	
    private TextField textField1;
    private TextField textField2;
    private TextField textField3;
    private TextField textField4;
    private TextField textField5;
    private TextField textField6;
    private TextField textField7;
    private TextField textField8;
    private TextField textField9;
    private TextField textField10;
    private TextArea textField11;
    private TreeItem<String> rootNode;
    private JsonNode rootNodeValue;
    private MenuButton menuButton;
	
	private static final String JSON_FILE_PATH = "SNMPv2-MIB.json";
	
	
	@Override
	public void start(Stage stage) {  
        menuButton = new MenuButton("Host");

        // Create menu items
        MenuItem item1 = new MenuItem("Item 1");
        MenuItem item2 = new MenuItem("Item 2");
        MenuItem item3 = new MenuItem("Item 3");

        // Add menu items to the menu button
        menuButton.getItems().addAll(item1, item2, item3);
		
		TreeView<String> treeView = new TreeView<>();
        treeView.setPrefSize(400, 200);//width, height
        
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonRoot = objectMapper.readTree(new File(JSON_FILE_PATH));

            rootNode = createTreeItem(jsonRoot);
            rootNodeValue = jsonRoot;
            treeView.setRoot(rootNode);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        treeView.setOnMouseClicked(event -> handleTreeItemClick(treeView.getSelectionModel().getSelectedItem()));
		//creating label and Text Field
		Text text1 = new Text("Name:");
		textField1 = new TextField();
		
		Text text2 = new Text("Oid:");
		textField2 = new TextField();
		
		Text text3 = new Text("Composed Type:");
		textField3 = new TextField();
		
		Text text4 = new Text("Base Type:");
		textField4 = new TextField();
		
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
		
		Text text10 = new Text("Module:");
		textField10 = new TextField();
		
		Text text11 = new Text("Description:");
		textField11 = new TextArea();
		textField11.setPrefColumnCount(31); // Set the preferred number of columns
		textField11.setPrefRowCount(3);
		
		//Creating a Grid Pane
		GridPane gridPane = new GridPane();
		
		//Setting size for the pane
		gridPane.setPrefSize(100,380);//width, height
		
		//Setting the padding	
		gridPane.setPadding(new Insets(5, 5, 5, 5));
		
		//Setting the vertical and horizontal gaps between the columns
		gridPane.setVgap(5);
		gridPane.setHgap(5);
		
		//Setting the Grid alignment
		gridPane.setAlignment(Pos.TOP_LEFT);
		
		//Arranging all the nodes in the grid
		gridPane.add(text1, 0, 0);
		gridPane.add(textField1, 1, 0);
		gridPane.add(text2, 0, 1);
		gridPane.add(textField2, 1, 1);
		gridPane.add(text3, 0, 2);
		gridPane.add(textField3, 1, 2);
		gridPane.add(text4, 0, 3);
		gridPane.add(textField4, 1, 3);
		gridPane.add(text5, 0, 4);
		gridPane.add(textField5, 1, 4);
		gridPane.add(text6, 0, 5);
		gridPane.add(textField6, 1, 5);
		gridPane.add(text7, 0, 6);
		gridPane.add(textField7, 1, 6);
		gridPane.add(text8, 0, 7);
		gridPane.add(textField8, 1, 7);
		gridPane.add(text9, 0, 8);
		gridPane.add(textField9, 1, 8);
		gridPane.add(text10, 0, 9);
		gridPane.add(textField10, 1, 9);
		gridPane.add(text11, 0, 10);
		gridPane.add(textField11, 1, 10);
		
		//Styling nodes		
		text1.setStyle("-fx-font: normal bold 12px 'serif' ");
		textField1.setStyle("-fx-font: normal bold 12px 'serif' ");
		text2.setStyle("-fx-font: normal bold 10px 'serif' ");
		text3.setStyle("-fx-font: normal bold 10px 'serif' ");
		text4.setStyle("-fx-font: normal bold 10px 'serif' ");
		text5.setStyle("-fx-font: normal bold 10px 'serif' ");
		text6.setStyle("-fx-font: normal bold 10px 'serif' ");
		text7.setStyle("-fx-font: normal bold 10px 'serif' ");
		text8.setStyle("-fx-font: normal bold 10px 'serif' ");
		text9.setStyle("-fx-font: normal bold 10px 'serif' ");
		text10.setStyle("-fx-font: normal bold 10px 'serif' ");
		text11.setStyle("-fx-font: normal bold 10px 'serif' ");

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
		//	gridPane.setMinSize(1000, 1000);	
		gridPane2.setPadding(new Insets(5, 5, 5, 5));	
		//Setting the vertical and horizontal gaps between the columns
		gridPane2.setVgap(5);
		gridPane2.setHgap(5);
		
		//Setting the Grid alignment
		gridPane2.setAlignment(Pos.TOP_LEFT);
		gridPane2.add(menuButton, 0, 0);
		gridPane2.add(treeView, 0, 1);
		gridPane2.add(gridPane, 0, 2);
//		gridPane2.add(hbox, 0, 3);
		
	    GridPane gridPane3 = new GridPane();
		gridPane3.setStyle("-fx-background-color: BEIGE;");
		gridPane1.setPrefSize(400, 600);	
		gridPane3.setPadding(new Insets(5, 5, 5, 5));	
		//Setting the vertical and horizontal gaps between the columns
		gridPane3.setVgap(5);
		gridPane3.setHgap(5);
		
		//Setting the Grid alignment
		gridPane3.setAlignment(Pos.TOP_LEFT);
		gridPane3.add(gridPane1, 1, 1);
		gridPane3.add(hbox, 1, 0);
		
		GridPane gridPane4 = new GridPane();
		gridPane4.setStyle("-fx-background-color: BEIGE;");
		//	gridPane.setMinSize(1000, 1000);	
		gridPane4.setPadding(new Insets(5, 5, 5, 5));	
		//Setting the vertical and horizontal gaps between the columns
		gridPane4.setVgap(5);
		gridPane4.setHgap(5);
		
		//Setting the Grid alignment
		gridPane4.setAlignment(Pos.TOP_LEFT);
		gridPane4.add(gridPane2, 0, 0);
		gridPane4.add(gridPane3, 1, 0);
		
		item1.setOnAction(event -> {
            menuButton.setText(item1.getText());
            // Add your custom logic here
        });

        item2.setOnAction(event -> {
            menuButton.setText(item2.getText());
            // Add your custom logic here
        });

        item3.setOnAction(event -> {
            menuButton.setText(item3.getText());
            // Add your custom logic here
        });
		
		gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
				button1.setOnAction(event -> {
				    String oid = textField2.getText() + ".0";
				    String result = snmpget.SnmpGet.snmpGet("192.168.56.1","public",oid);
				    textField12.setText(result);
				});
			}});
			
		gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
				button2.setOnAction(event -> {
				    String oid = textField2.getText() + ".0";
				    String result = snmpgetnext.SnmpGetNext.snmpGetNext("192.168.56.1","public",oid);
				    textField12.setText(result);
				});
			}});
			
		gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
				button3.setOnAction(event -> {
				    String oid = textField2.getText();
				    String result = snmpwalk.SnmpWalk.snmpWalk("192.168.56.1","public",oid);
				    textField12.setText(result);
				});
			}});
				
		BorderPane root = new BorderPane();
	    root.setTop(gridPane4);
		
		//Creating a scene object
		Scene scene1 = new Scene(root,840,630);//width,height
		
		//Setting title to the Stage
		stage.setTitle("Snmp");
		
		//Adding scene to the stage
		stage.setScene(scene1);
		
		//Displaying the contents of the stage
		stage.show();
	}
	
    private TreeItem<String> createTreeItem(JsonNode node) {
        TreeItem<String> item = new TreeItem<>(node.getNodeType().toString());

        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                TreeItem<String> childItem = createTreeItem(entry.getValue());
                childItem.setValue(entry.getKey());
                item.getChildren().add(childItem);
            });
        } else if (node.isArray()) {
            for (JsonNode childNode : node) {
                TreeItem<String> childItem = createTreeItem(childNode);
                item.getChildren().add(childItem);
            }
        } else {
            item.setValue(node.asText());
        }

        return item;
    }
    
    private void handleTreeItemClick(TreeItem<String> selectedItem) {
        if (selectedItem != null) {
            if (selectedItem.getParent() != null && selectedItem.getParent() == rootNode) {
                JsonNode selectedNode = findNodeByPath(selectedItem.getValue());

                if (selectedNode != null) {
                    String text1 = selectedNode.get("name").asText();
                    String text2 = selectedNode.get("oid").asText();
                    
                    JsonNode nodeNode = selectedNode.get("nodetype");
                    if (nodeNode != null) {
                        String text3 = selectedNode.get("nodetype").asText();
                        textField7.setText(text3);
                    }
                    
                    JsonNode maxAccessNode = selectedNode.get("maxaccess");
                    
                    if (maxAccessNode != null) {
                    	String text6 = selectedNode.get("maxaccess").asText();
                    	textField6.setText(text6); 
                    }
                    
                    JsonNode statusNode = selectedNode.get("status");
                    if (statusNode != null ) {
                    	String text7 = selectedNode.get("status").asText();
                    	textField5.setText(text7);
                    }
                    
                    JsonNode descriptionNode = selectedNode.get("description");
                    if (descriptionNode != null) {
                    	String text8 = selectedNode.get("description").asText();
                    	textField11.setText(text8);
                    }
                    String text4 = selectedNode.get("class").asText();
                    
                    JsonNode syntaxNode = selectedNode.get("syntax");
                    if (syntaxNode != null && syntaxNode.has("constraints") && syntaxNode.has("type")) {
                        JsonNode constraintsNode = syntaxNode.get("constraints");
                        String text5 = selectedNode.get("syntax").get("type").asText();
                        textField3.setText(text5);
                        if (constraintsNode != null && constraintsNode.has("size")) {
                            JsonNode sizeNode = constraintsNode.get("size");
                            if (sizeNode.isArray() && sizeNode.size() > 0) {
                                JsonNode minNode = sizeNode.get(0).get("min");
                                JsonNode maxNode = sizeNode.get(0).get("max");
                                if (minNode != null && maxNode != null) {
                                	String text9 = selectedNode.get("syntax").get("constraints").get("size").get(0).get("min").asText();
                                    String text10 = selectedNode.get("syntax").get("constraints").get("size").get(0).get("max").asText();
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

    private JsonNode findNodeByPath(String path) {
        String[] parts = path.split("\\.");

        JsonNode currentNode = rootNodeValue;
        for (String part : parts) {
            if (currentNode.has(part)) {
                currentNode = currentNode.get(part);
            } else {
                return null;
            }
        }
        return currentNode;
    }
    
	public static void main(String args[]){
	launch(args);
	}	
}
