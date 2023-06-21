package snmpgui;

import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

public class OtherClass {
    private Stage stage;

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    public void moveToOtherClass() {
        // Create a button
        Button backButton = new Button("Go Back");
        backButton.setOnAction(event -> {
            // Close the current stage and show the main stage
            stage.close();
        });

        // Create the layout
        StackPane root = new StackPane(backButton);

        // Create the scene
        Scene scene = new Scene(root, 300, 200);

        // Set the scene on the stage
        stage.setScene(scene);
        stage.setTitle("Other Class");
        stage.show();
    }
}

