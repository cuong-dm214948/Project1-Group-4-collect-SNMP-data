package snmpgui;

import javafx.scene.control.Label;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.stage.Stage;

import org.json.simple.JSONObject;
import java.io.File;
import java.io.IOException;

public class MIBTreeGUI extends Application {
	private Label nodeInfoLabel;

    private static final String JSON_FILE_PATH = "MIB.json";


    @Override
    public void start(Stage primaryStage) {
        TreeView<String> treeView = new TreeView<>();
        treeView.setPrefSize(400, 600);

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(new File(JSON_FILE_PATH));

            TreeItem<String> rootItem = createTreeItem(rootNode);
            treeView.setRoot(rootItem);
        } catch (IOException e) {
            e.printStackTrace();
        }

        primaryStage.setScene(new Scene(treeView));
        primaryStage.setTitle("MIB Tree");
        primaryStage.show();
        
        treeView.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue != null) {
                String nodeInfo = extractNodeInformation(newValue); // Extract the relevant information from the selected node
                nodeInfoLabel.setText(nodeInfo); // Update the nodeInfoLabel with the selected node information
            }
        });
        
        nodeInfoLabel = new Label();
        layout.setBottom(nodeInfoLabel);
        
        private String extractNodeInformation(TreeItem<String> node) {
            String nodeValue = node.getValue();
            JSONObject nodeJson = new JSONObject(nodeValue);

            StringBuilder information = new StringBuilder();
            information.append("OBJECT-TYPE\n");
            information.append("SYNTAX: ").append(nodeJson.getJSONArray("SYNTAX").toString()).append("\n");
            information.append("MAX-ACCESS: ").append(nodeJson.getString("MAX-ACCESS")).append("\n");
            information.append("STATUS: ").append(nodeJson.getString("STATUS")).append("\n");
            information.append("DESCRIPTION:\n");
            JSONArray descriptionArray = nodeJson.getJSONArray("DESCRIPTION");
            for (int i = 0; i < descriptionArray.length(); i++) {
                information.append("- ").append(descriptionArray.getString(i)).append("\n");
            }

            return information.toString();
        }
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
    
    public static void main(String[] args) {
        launch(args);
    }
}



