//Autorzy: Wojciech Blyskal 247632, Hanna Tovstokora 245114
package com.example.kryptografia;

import java.io.*;

public class IOService {

    public static void saveToFile(byte[] data, String fileName) throws IOException {
        File file = new File(fileName);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }

    public static byte[] readFromFile(String fileName) throws IOException {
        File file = new File(fileName);
        byte[] data;
        try (FileInputStream fis = new FileInputStream(file)) {
            data = new byte[(int) file.length()];
            fis.read(data);
        }
        return data;
    }
}
