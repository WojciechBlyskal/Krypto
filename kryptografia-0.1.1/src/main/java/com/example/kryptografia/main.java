package com.example.kryptografia;
import java.lang.*;

public class main {
    public static void main(String[] args) {
        DESX des = new DESX();
        byte[] bytes = new byte[8];//{0, 0, 0, 0, 63, 63, 63, 63};
        bytes[0] = (byte) 255;
        /*byte[] key = new byte[8];
        key[0] = 19;
        key[1] = 52;
        key[2] = 87;
        key[3] = 121;
        key[4] = (byte) 155;
        key[5] = (byte) 188;
        key[6] = (byte) 223;
        key[7] = (byte) 241;

        des.generate16Keys(key);*/
        //00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001
        //bytes[4] = 63;
        /*des.setBit(bytes, 4, true);
        des.printBits(bytes);
        if (des.isBitSet(bytes, 4)) {
            System.out.println("Yes");
        }*/
        //des.printBits(bytes);
        //des.printBits(des.circularLeftShift(bytes, 64));
        /*byte[] initialText = new byte[8];
        initialText[0] = 1;
        initialText[1] = 35;
        initialText[2] = 69;
        initialText[3] = 103;
        initialText[4] = (byte) 137;
        initialText[5] = (byte) 171;
        initialText[6] = (byte) 205;
        initialText[7] = (byte) 239;
        des.encoding(initialText);*/
        byte[] feistelHalf = new byte[4];
        feistelHalf[0] = (byte) 240;
        feistelHalf[1] = (byte) 170;
        feistelHalf[2] = (byte) 240;
        feistelHalf[3] = (byte) 170;

        byte[] key2 = new byte[6];
        key2[0] = 27;
        key2[1] = 2;
        key2[2] = (byte) 239;
        key2[3] = (byte) 252;
        key2[4] = 112;
        key2[5] = 114;
        // 00011011 00000010 11101111 11111100 01110000 01110010

        des.FeistelFunction(feistelHalf, key2);
        //des.printBits(des.XOR(key, bytes));
    }
}
