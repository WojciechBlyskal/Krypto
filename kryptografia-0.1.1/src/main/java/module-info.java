module com.example.kryptografia {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.kryptografia to javafx.fxml;
    exports com.example.kryptografia;
}