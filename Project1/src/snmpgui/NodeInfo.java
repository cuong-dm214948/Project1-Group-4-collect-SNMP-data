package snmpgui;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;

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

public class NodeInfo {
	
	

    public void initializeTrap(VBox vbox) {
    	Label text1 = new Label();
        Label text2 = new Label();
        Label text3 = new Label();
        TextArea textField1 = new TextArea();
        TextArea textField2 = new TextArea();
        TextArea textField3 = new TextArea();
        
        text1.setText("Trap log");
        text2.setText("Trap content");
        text3.setText("Trap info");
        
		textField1.setPrefColumnCount(70); // Set the preferred number of columns
		textField1.setPrefRowCount(15);
		textField2.setPrefColumnCount(33); // Set the preferred number of columns
		textField2.setPrefRowCount(15);
		textField3.setPrefColumnCount(33); // Set the preferred number of columns
		textField3.setPrefRowCount(15);
		
		//Creating a Grid Pane
		GridPane gridPane = new GridPane();
		
		//Setting size for the pane
		gridPane.setPrefSize(1000,300);//width, height
		
		//Setting the padding	
		gridPane.setPadding(new Insets(5, 5, 5, 5));
		
		//Setting the vertical and horizontal gaps between the columns
		gridPane.setVgap(5);
		gridPane.setHgap(5);
		
		//Setting the Grid alignment
		gridPane.setAlignment(Pos.TOP_LEFT);
		
		//Arranging all the nodes in the grid
		gridPane.add(text1, 0, 0);
		gridPane.add(textField1, 0, 1);
		
		//Styling nodes		
		text1.setStyle("-fx-font: normal bold 14px 'serif' ");
		gridPane.setStyle("-fx-background-color: BEIGE;");
		
		GridPane gridPane1 = new GridPane();
		
		//Setting size for the pane
		gridPane1.setPrefSize(400,300);//width, height
		
		//Setting the padding	
		gridPane1.setPadding(new Insets(5, 5, 5, 5));
		
		//Setting the vertical and horizontal gaps between the columns
		gridPane1.setVgap(5);
		gridPane1.setHgap(5);
		
		//Setting the Grid alignment
		gridPane1.setAlignment(Pos.TOP_LEFT);
		
		//Arranging all the nodes in the grid
		gridPane1.add(text2, 0, 0);
		gridPane1.add(textField2, 0, 1);
		gridPane1.add(text3, 1, 0);
		gridPane1.add(textField3, 1, 1);
		
		text2.setStyle("-fx-font: normal bold 14px 'serif' ");
		text3.setStyle("-fx-font: normal bold 14px 'serif' ");

		gridPane1.setStyle("-fx-background-color: BEIGE;");
		
		GridPane gridPane2 = new GridPane();
		
		//Setting size for the pane
		gridPane2.setPrefSize(1000,800);//width, height
		
		//Setting the padding	
		gridPane2.setPadding(new Insets(5, 5, 5, 5));
		
		//Setting the vertical and horizontal gaps between the columns
		gridPane2.setVgap(5);
		gridPane2.setHgap(5);
		
		//Setting the Grid alignment
		gridPane2.setAlignment(Pos.TOP_LEFT);
		
		//Arranging all the nodes in the grid
		gridPane2.add(gridPane, 0, 0);
		gridPane2.add(gridPane1, 0, 1);

		gridPane2.setStyle("-fx-background-color: BEIGE;");
    
        vbox.getChildren().addAll(gridPane2);
    }
}