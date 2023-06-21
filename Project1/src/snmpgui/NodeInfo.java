package snmpgui;

import javafx.application.Application;
import javafx.event.EventHandler;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.scene.control.TextArea;

public class NodeInfo extends Application {
	private String name;
	private String ipAddress;
	private String community;
	private String port;
	
	public NodeInfo(String name,String ipAddress,String community,String port) {
		this.name=name;
		this.ipAddress=ipAddress;
		this.community=community;
		this.port=port;
	}
	@Override
	public void start(Stage stage) {
	//creating label and Text Field
	Text text1 = new Text("Name:");
	TextField textField1 = new TextField();
	
	Text text2 = new Text("Oid:");
	TextField textField2 = new TextField();
	
	Text text3 = new Text("Composed Type:");
	TextField textField3 = new TextField();
	
	Text text4 = new Text("Base Type:");
	TextField textField4 = new TextField();
	
	Text text5 = new Text("Status:");
	TextField textField5 = new TextField();
	
	Text text6 = new Text("Access:");
	TextField textField6 = new TextField();
	
	Text text7 = new Text("Kind:");
	TextField textField7 = new TextField();
	
	Text text8 = new Text("SMI type:");
	TextField textField8 = new TextField();
	
	Text text9 = new Text("Size:");
	TextField textField9 = new TextField();
	
	Text text10 = new Text("Module:");
	TextField textField10 = new TextField();
	
	Text text11 = new Text("Description:");
	TextArea textField11 = new TextArea();
	
	//Creating a Grid Pane
	GridPane gridPane = new GridPane();
	
	//Setting size for the pane
//	gridPane.setMinSize(1000, 1000);
	
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
	
	text1.setStyle("-fx-font: normal bold 14px 'serif' ");
	textField1.setStyle("-fx-font: normal bold 14px 'serif' ");
	text2.setStyle("-fx-font: normal bold 14px 'serif' ");
	text3.setStyle("-fx-font: normal bold 14px 'serif' ");
	text4.setStyle("-fx-font: normal bold 14px 'serif' ");
	text5.setStyle("-fx-font: normal bold 14px 'serif' ");
	text6.setStyle("-fx-font: normal bold 14px 'serif' ");
	text7.setStyle("-fx-font: normal bold 14px 'serif' ");
	text8.setStyle("-fx-font: normal bold 14px 'serif' ");
	text9.setStyle("-fx-font: normal bold 14px 'serif' ");
	text10.setStyle("-fx-font: normal bold 14px 'serif' ");
	text11.setStyle("-fx-font: normal bold 14px 'serif' ");

	gridPane.setStyle("-fx-background-color: BEIGE;");
	gridPane.setId("Node Information");
	
	//creating getconnection
	GridPane gridPane1 = new GridPane();
	gridPane1.setStyle("-fx-background-color: BEIGE;");
	//	gridPane.setMinSize(1000, 1000);	
	gridPane1.setPadding(new Insets(5, 5, 5, 5));	
	//Setting the vertical and horizontal gaps between the columns
	gridPane1.setVgap(5);
	gridPane1.setHgap(5);
	gridPane1.setId("Query results");
	
	//Setting the Grid alignment
	gridPane1.setAlignment(Pos.TOP_RIGHT);
	Text text12 = new Text("Query result:");
	TextArea textField12 = new TextArea();
	
	gridPane1.add(text12, 2, 0);
	gridPane1.add(textField12, 2, 1);
	
	
	//Creating Buttons
	Button button1 = new Button("    Get    ");
	Button button2 = new Button("  GetNext  ");
	Button button3 = new Button("    Walk   ");
	button1.setStyle("-fx-background-color: darkslateblue; -fx-text-fill: white;");
	button2.setStyle("-fx-background-color: darkslateblue; -fx-text-fill: white;");
	button3.setStyle("-fx-background-color: darkslateblue; -fx-text-fill: white;");
	HBox hbox = new HBox(100,button1,button2,button3);
	hbox.setPadding(new Insets(0));
    hbox.setAlignment(Pos.TOP_LEFT);
    hbox.setStyle("-fx-background-color: BEIGE;");
	
	gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
		@Override
		public void handle(MouseEvent arg0) {
			button1.setOnAction(event -> {
			    String oid = textField2.getText();
			    String result = snmpget.SnmpGet.snmpGet(ipAddress,community,oid);
			    textField12.setText(result);
			});
		}});
		
	gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
		@Override
		public void handle(MouseEvent arg0) {
			button2.setOnAction(event -> {
			    String oid = textField2.getText();
			    String result = snmpgetnext.SnmpGetNext.snmpGetNext(ipAddress,community,oid);
			    textField12.setText(result);
			});
		}});
		
	gridPane.addEventFilter(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
		@Override
		public void handle(MouseEvent arg0) {
			button3.setOnAction(event -> {
			    String oid = textField2.getText();
			    String result = snmpwalk.SnmpWalk.snmpWalk(ipAddress,community,oid);
			    textField12.setText(result);
			});
		}});
	
	
	BorderPane root = new BorderPane();
    root.setTop(gridPane);
    root.setLeft(hbox);
    root.setRight(gridPane1);
	
	//Creating a scene object
	Scene scene1 = new Scene(root,1000,600);//width,height
	
	//Setting title to the Stage
	stage.setTitle("Snmp");
	
	//Adding scene to the stage
	stage.setScene(scene1);
	
	//Displaying the contents of the stage
	stage.show();
	}
	public static void main(String args[]){
	launch(args);
	}
	
}