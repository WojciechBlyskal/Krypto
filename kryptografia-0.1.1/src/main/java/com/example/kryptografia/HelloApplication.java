package com.example.kryptografia;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class HelloApplication extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("MainWindow.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 900, 680);
        stage.setTitle("Szyfrowanie DESX");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}