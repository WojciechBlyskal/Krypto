package com.example.kryptografia;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MainWindowController {

    @FXML
    private TextArea plainTextTextAreaID;

    @FXML
    private TextArea cipherTextTextAreaID;

    @FXML
    private TextField keyIntTextFieldID;

    @FXML
    private TextField keyDesTextFieldID;

    @FXML
    private TextField keyExtTextFieldID;

    @FXML
    private Label actualIntKeyLabelID;
    @FXML
    private Label actualDesKeyLabelID;
    @FXML
    private Label actualExtKeyLabelID;


    private byte[] mess = null;

    private byte[] cipher = null;

    private byte[] keyIntCtrl = null;

    private byte[] keyExtCtrl = null;

    private byte[] keyDesCtrl = null;

    DESX desx;

    @FXML
    public void initialize() {
        desx = new DESX();
    }

    private void messageBox(String title, String message, Alert.AlertType alertType) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    @FXML
    private void onEncryptFromInputButtonClick() {
        if (desx.getKeyExt() != null && desx.getKeyInt() != null && desx.getKeyDes() != null) {
            if (!plainTextTextAreaID.getText().isEmpty()) {
                if (mess == null) {
                    mess = plainTextTextAreaID.getText().getBytes(StandardCharsets.UTF_8);
                }
                cipher = desx.finalEncryption(mess);
                cipherTextTextAreaID.setText(desx.bytesToHex(cipher));
            }
        }
        else {
            messageBox("Nie ustawiono kluczy", "Przed szyfrowaniem nalezy zatwierdzic 3 klucze", Alert.AlertType.INFORMATION);
        }
    }

    @FXML
    private void onDecryptFromInputButtonClick() {
        if (desx.getKeyExt() != null && desx.getKeyInt() != null && desx.getKeyDes() != null) {
            if (cipher != null) {
                mess = desx.finalDecryption(cipher);
                plainTextTextAreaID.setText(new String(mess));
            } else {
                messageBox("Brak szyfru", "Najpierw należy przeprowadzić szyfrowanie \nlub wczytać szyfr z pliku", Alert.AlertType.INFORMATION);
            }

        } else {
            messageBox("Nie ustawiono kluczy", "Przed deszyfrowaniem nalezy zatwierdzic 3 klucze", Alert.AlertType.INFORMATION);
        }
    }


    @FXML
    private Stage primaryStage;

    @FXML
    private void onEncryptFromFileButtonClick() {

        FileChooser fileChooser = new FileChooser();

        fileChooser.setTitle("Wybierz plik do szyfrowania");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Pliki tekstowe", "*.pdf"),
                new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );

        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        if (selectedFile != null) {
            try {
                String filePath = selectedFile.getAbsolutePath();

                mess = IOService.readFromFile(filePath);

                String plainText = new String(desx.bytesToHex(mess));

                plainTextTextAreaID.setText(plainText);
            } catch (IOException e) {
                messageBox("Blad wczytywania", "Nie udalo sie wczytac", Alert.AlertType.ERROR);
            }
        }
    }


    @FXML
    private void onSaveDecryptedToFileButtonClick() {

        if (mess != null) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Wybierz miejsce do zapisania");
            fileChooser.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("Pliki tekstowe", "*.pdf"),
                    new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
            );

            File selectedFile = fileChooser.showSaveDialog(primaryStage);

            if (selectedFile != null) {
                try {
                    if (!selectedFile.exists()) {
                        selectedFile.createNewFile();
                    }
                    String filePath = selectedFile.getAbsolutePath();

                    IOService.saveToFile(mess, filePath);
                } catch (IOException e) {
                    messageBox("Blad zapisu", "Nie udalo sie zapisac", Alert.AlertType.ERROR);
                }
            }
        }
    }

    @FXML
    private void onDecryptFromFileButtonClick() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );

        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        if (selectedFile != null) {
            try {
                String filePath = selectedFile.getAbsolutePath();

                cipher = IOService.readFromFile(filePath);

                String cipherText = new String(cipher, StandardCharsets.UTF_8);

                cipherTextTextAreaID.setText(cipherText);
            } catch (IOException e) {
                messageBox("Blad wczytywania", "Nie udalo sie wczytac", Alert.AlertType.ERROR);
            }
        }
    }

    @FXML
    private void onSaveEncryptedToFileButtonClick() {
        if (cipher != null) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Wybierz miejsce do zapisania");
            fileChooser.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt"),
                    new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
            );

            File selectedFile = fileChooser.showSaveDialog(primaryStage);

            if (selectedFile != null) {
                try {

                    if (!selectedFile.exists()) {
                        selectedFile.createNewFile();
                    }
                    String filePath = selectedFile.getAbsolutePath();

                    IOService.saveToFile(cipher, filePath);

                } catch (IOException e) {
                    messageBox("Blad zapisu", "Nie udalo sie zapisac pliku", Alert.AlertType.ERROR);
                }
            }
        } else {
            messageBox("Brak szyfru do zapisu", "Nie wykonano szyfrowania", Alert.AlertType.ERROR);
        }
    }

    @FXML
    private void onReadKeysFromFileButton() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz miejsce z zapisanymi kluczami");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt")
        );

        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        if (selectedFile != null) {
            try {
                String filePath = selectedFile.getAbsolutePath();

                byte[] combined = IOService.readFromFile(filePath);

                byte[] tempKey1 = new byte[8];
                byte[] tempKey2 = new byte[8];
                byte[] tempKey3 = new byte[8];

                System.arraycopy(combined, 0, tempKey1, 0, 8);
                System.arraycopy(combined, 8, tempKey2, 0, 8);
                System.arraycopy(combined, 16, tempKey3, 0, 8);

                String str = desx.bytesToHex(tempKey1);
                keyIntTextFieldID.setText(str);
                str = desx.bytesToHex(tempKey2);
                keyDesTextFieldID.setText(str);
                str = desx.bytesToHex(tempKey3);
                keyExtTextFieldID.setText(str);

            } catch (IOException e) {
                messageBox("Problem z wczytaniem", "Wystapil problem z wczytaniem", Alert.AlertType.ERROR);
            }
        }


    }

    @FXML
    private void onSaveKeysToFileButton() {

        if (desx.getKeyExt() != null && desx.getKeyInt() != null && desx.getKeyDes() != null) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Wybierz miejsce do zapisania kluczy");
            fileChooser.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt")
            );

            File selectedFile = fileChooser.showSaveDialog(primaryStage);

            if (selectedFile != null) {
                try {
                    if (!selectedFile.exists()) {
                        selectedFile.createNewFile();
                    }

                    String filePath = selectedFile.getAbsolutePath();

                    byte[] combined = new byte[24];

                    System.arraycopy(desx.getKeyInt(), 0, combined, 0, 8);
                    System.arraycopy(desx.getKeyDes(), 0, combined, 8, 8);
                    System.arraycopy(desx.getKeyExt(), 0, combined, 16, 8);

                    IOService.saveToFile(combined, filePath);

                } catch (IOException e) {
                    messageBox("Problem z zapisem", "Wystapil problem z zapisem", Alert.AlertType.ERROR);
                }
            }
        } else {
            messageBox("Brak potwierdzonych kluczy", "Nie zostały zatwierdzone żadne klucze", Alert.AlertType.ERROR);
        }

    }


    @FXML
    private void onKeyIntButtonClick() {

        String str = desx.bytesToHex(desx.generateKey());
        keyIntTextFieldID.setText(str);
    }

    @FXML
    private void onKeyDesButtonClick() {
        String str = desx.bytesToHex(desx.generateKey());
        keyDesTextFieldID.setText(str);
    }

    @FXML
    private void onKeyExtButtonClick() {

        String str = desx.bytesToHex(desx.generateKey());
        keyExtTextFieldID.setText(str);
    }

    @FXML
    private void onKeyConfirmationButtonClick() {


        String temp = keyIntTextFieldID.getText();
        if (temp.length() != 16) {
            messageBox("Niepoprawna dlugosc", "Klucz Int jest zbyt dlugi lub zbyt krotki", Alert.AlertType.ERROR);

        } else {
            try {
                keyIntCtrl = desx.hexToBytes(temp);

                desx.setKeyInt(keyIntCtrl);
                actualIntKeyLabelID.setText(desx.bytesToHex(keyIntCtrl));
            } catch (NumberFormatException e) {
                messageBox("Niepoprawne znaki", "Klucz Int posiada znaki nie pasujace do systemu HEX", Alert.AlertType.ERROR);

            }
        }
        temp = keyDesTextFieldID.getText();
        if (temp.length() != 16) {
            messageBox("Niepoprawna dlugosc", "Klucz Des jest zbyt dlugi lub zbyt krotki", Alert.AlertType.ERROR);

        } else {
            try {
                keyDesCtrl = desx.hexToBytes(temp);
                desx.setKeyDes(keyDesCtrl);
                actualDesKeyLabelID.setText(desx.bytesToHex(keyDesCtrl));
            } catch (NumberFormatException e) {
                messageBox("Niepoprawne znaki", "Klucz Des posiada znaki nie pasujace do systemu HEX", Alert.AlertType.ERROR);

            }
        }
        temp = keyExtTextFieldID.getText();
        if (temp.length() != 16) {
            messageBox("Niepoprawna dlugosc", "Klucz Ext jest zbyt dlugi lub zbyt krotki", Alert.AlertType.ERROR);

        } else {
            try {
                keyExtCtrl = desx.hexToBytes(temp);
                desx.setKeyExt(keyExtCtrl);
                actualExtKeyLabelID.setText(desx.bytesToHex(keyExtCtrl));
            } catch (NumberFormatException e) {
                messageBox("Niepoprawne znaki", "Klucz Ext posiada znaki nie pasujace do systemu HEX", Alert.AlertType.ERROR);

            }
        }

    }

}
