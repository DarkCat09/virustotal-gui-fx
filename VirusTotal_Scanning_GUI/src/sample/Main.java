package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        primaryStage.setTitle("VirusTotal - File Scanning");
        primaryStage.setScene(new Scene(root, 350, 150));
        primaryStage.show();
    }


    public static void main(String[] args) {
        //System.out.println();
        //System.out.println("--- VirusTotal File Scanning GUI ---");
        //System.out.println("-------- v.1.0 by DarkCat09 --------");
        //System.out.println();
        launch(args);
    }
}
