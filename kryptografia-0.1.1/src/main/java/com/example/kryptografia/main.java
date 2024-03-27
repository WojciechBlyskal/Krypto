package com.example.kryptografia;
import java.lang.*;

public class main {
    public static void main(String[] args) {
        DESX des = new DESX();
        byte[] bytes = new byte[]{0, 0, 0, 63, 63, 63, 63, 63};
        for (int i = 0; i < 8; i++) {
            System.out.println(String.valueOf(bytes[i]));
        }
        if (des.isBitSet(bytes, 0)) {
            System.out.print("1");
        } else {
            System.out.print("0");
        }

    }
}
