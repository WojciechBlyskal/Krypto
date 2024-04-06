package com.example.kryptografia;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.security.NoSuchAlgorithmException;

public class DESX {

    byte[][] subKeys;

    DESX() {
        subKeys = new byte[16][6];
    }

    private byte[] PC1 = {
        57, 49, 41, 33, 25, 17,  9,  1,
        58, 50, 42, 34, 26, 18, 10,  2,
        59, 51, 43, 35, 27, 19, 11,  3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15,  7, 62, 54, 46, 38,
         0, 22, 14,  6, 61, 53, 45, 37,
        29, 21, 13,  5, 28, 20, 12,  4
    };

    private byte[] LeftShifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    private byte[] PC2 = {
            14, 17, 11, 24,  1,  5,  3, 28,
            15,  6, 21, 10, 23, 19, 12,  4,
            26,  8, 16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
    };

    private byte[] initPermutation = {
            58,	50,	42,	34,	26,	18,	10,	2,
            60,	52,	44,	36,	28,	20,	12,	4,
            62,	54, 46, 38,	30, 22, 14, 6,
            64,	56,	48,	40,	32,	24,	16,	8,
            57,	49,	41,	33,	25,	17,	9,	1,
            59,	51,	43,	35,	27,	19,	11,	3,
            61,	53,	45,	37,	29,	21,	13,	5,
            63,	55,	47,	39,	31,	23,	15,	7
    };

    private byte[] EBitSelectionTable = {
            32,  1,  2,  3,  4,  5,  4,  5,
             6,  7,  8,  9,  8,  9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32,  1
    };

    private byte[] SBoxes = {
            14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7, // S1
             0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
             4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
            15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
            15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10, // S2
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
            10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8, // S3
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
             7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15, // S4
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
             3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
             2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9, // S5
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
             4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
            12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11, // S6
            10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
             9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
             4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1, // S7
            13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
            13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7, // S8
             1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    };

    public boolean isBitSet (byte[] bytes, int position) {  //sprawdza czy bit na danej pozycji wynosi 0 czy 1
        byte auxByte = bytes[position / 8]; //np. dla position=50 auxByte=50:8=6, czyli poszukiwany bit jest w bajcie nr 6(czyli siodmym)
        byte auxPosition = (byte) (position % 8);   //np. dla position=50 auxPosition=50%8=2, czyli poszukiwany bit jest w bajcie bitem nr 2(czyli trzecim)
        return ((auxByte & (1 << (7 - auxPosition))) != 0); //1 << (7 - auxPosition) przesuwa 1 w 00000001 by znalazla sie na pozycji wskazanej przez auxPosition
        //np. dla auxPosition=2 7-2=5 00000001->00100000. Nastepnie dokonujemy iloczynu bitowego z wlasciwym bajtem.
        // & 1 << (7 -auxPosition) wyzeruje wszystkie bity w auxByte poza tym, ktory jest zgodny z auxPosition.
        //W efekcie jesli na pozycji auxPosition w auxByte jest 0, to iloczyn zwroci 0, w przeciwnym razie zwroci calkowita potege 2, ale interesuje nas
        //tylko to, ze nie zwroci 0, wiec bit na tej pozycji jest ustawiony na 1
    }

    public byte[] setBit (byte[] bytes, int position, boolean value) {  //ustawia bit w tablicy bajtow na podanej pozycji na wskazana wartosc
        byte auxByte = bytes[position / 8];         //wyjasnione w funkcji isBitSet
        byte auxPosition = (byte) (position % 8);   //wyjasnione w funkcji isBitSet
        if (value) {    // w zaleznosci na jaka wartosc chcemy zmienic wartosc bitu wchodzimy do odpowiedniego if
            bytes[position / 8] = (byte) (auxByte | (1 << (7 - auxPosition)));  //nie korzystamy z auxByte po lewej stornie przypisania, bo chcemy zmienic wartosc bitu
            //w oryginalnej tablicy. auxByte | (1 << (7 - auxPosition)) dziala inaczej niz isBitSet, gdyz stosujemy alternatywe('|'), by zachowac z oryginalnego
            //bajtu 1 na wszystkich pozycjach na ktorych juz byly. Dzieki temu i dzeki (1 << (7 - auxPosition)) dajacemu np. 00100000 alternatywa ta zmieni oryginalny
            //bajt tylko na wskazanej pozycji(jesli np. 11011011 i position=2 metoda zwroci 11111011). W przypadku gdy na wskazanym bicie jest juz 1, bajt zostanie
            //nie zmieniony (dla np. 11011011 i position=1 metoda zwroci 11011011).
        } else {
            bytes[position / 8] = (byte) (auxByte & (~(1 << (7 - auxPosition))));   //teraz stosujemy koniunkcje('&'), by w razie wystapienia 1 na pozycji ktora chcemy
            //zmienic zastapic ja 0. Aby jednak 1 na pozostalych pozycjach zostalo zachowane to (1 << (7 - auxPosition)) musi zostac zanegowane(np. jesli position=2,
            //dostajemy 11011111, ktore pozostawi 1 w miejscach w ktorych byly wczesniej, poza miejscem wskazanym do zmiany).
        }
        return bytes;
    }

    public byte setBit (byte bytes, int position, boolean value) {  //metoda analogiczna do drugiego setBit, ale gdy poslugujemy sie pojedynczym bajtem a nie tablica bajtow
        if (value) {
            return (byte) (bytes | (1 << position));
        } else {
            return (byte) (bytes & (~(1 << position)));
        }
    }

    public void printBits(byte[] data) { //przyjmuje dowolna dlugosc bytow, przygotowane bylo pod wyswietlanie 8 bytow
        int len = data.length;
        printNum(8 * len);
        for (int i = 0; i < 8 * len; i++) {
            if (isBitSet(data, i)) {
                System.out.print("1  ");
            } else {
                System.out.print("0  ");
            }
        }
        System.out.println();
    }

    private void printNum(int len) {
        for (int i = 0; i < len; i++) {
            System.out.print(i+" ");
            if (i < 10) {
                System.out.print(" ");
            }
        }
        System.out.println();
    }

    public byte[] circularLeftShift(byte[] bytes, int amount) { //celem metody jest przerobienie oryginalnej tablicy bajtow tak,
        // by przesunac bity w lewo w kazdym bajcie, a utracone bity zostaly zapisane w po prawej
        byte[] shifted = new byte[bytes.length]; //zmienna przechowuje bajty z oryginalnej tablicy
        byte step = (byte) (bytes.length * 8 - amount); //step zachowa te bajty ktore po przesunieciu nie beda przenoszone na prawa strone

        System.arraycopy(bytes, 0, shifted, 0, bytes.length);
        for (int i = 0; i < bytes.length; i++) { // iteracja po kolejnych bajtach tablicy
            shifted[i] = (byte) (shifted[i] << 1);
            if (i + 1 < bytes.length) {
                shifted = setBit(shifted, 8 * i + 7, isBitSet(bytes, 8 * i + 8));
            } else {
                shifted = setBit(shifted, 8 * i + 7 - step, isBitSet(bytes, 0));
            }
        }
        return shifted;
    }

    /*public byte[] circularLeftShift(byte[] data, int dataLen) {
        byte[] res = new byte[data.length];
        byte step = (byte) (data.length * 8 - dataLen);

        System.arraycopy(data, 0, res, 0, data.length);

        for (int i = 0; i < data.length; i++) {
            res[i] = (byte) (res[i] << 1);
            if (i + 1 < data.length) {
                res = setBit(res, 8 * i + 7, isBitSet(data, 8 * i + 8));
            } else {
                res = setBit(res, 8 * i + 7 - step, isBitSet(data, 0));
            }
        }
        return res;
    }*/

    public byte[] inititalPermutation(byte[] _8Bytes) {
        byte[] local = new byte[8];
        for (int i = 0; i < 64; i++) {
            local = setBit(local, i, isBitSet(_8Bytes, PC1[i] - 1));
        }
        return local;
    }

    public byte[] endingPermutation(byte[] _8Bytes) {
        byte[] local = new byte[8];
        for (int i = 0; i < 64; i++) {
            local = setBit(local, i, isBitSet(_8Bytes, PC2[i] - 1));
        }
        return local;
    }

    public byte[] generateKey() {   //tworzymy klucz dzieki bibliotece
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void generate16Keys (byte[] key64) { //przerobic 64bitowy klucz na klucz 56bitowy, podzielic go na 2 klucze 28bitowe, tymi
        //dwoma kluczami wygenerowac zestaw 16 kluczy 56bitowych a ten zestaw przerobic na 16 kluczy 48bitowych
        byte[] key56 = new byte[7];

        for (int i = 0; i < 7; i++) { //generowanie klucza 56 bitowego. Iterujac ustawiamy kolejne bity klucza 56bitowego z odpowiednich bitow
            // klucza 64bitowego. Kolejnosc bitow(wraz z wyborem bitow do odrzucenia) mamy zdefiniowana w tablicy PC1. Tablica PC1 jest z gory
            // ustalona dla algorytmu, ale trzeba od nr bitu wskazanego przez nia odjac 1, gdyz nr bitow w tablicy sa numerowane od 1 do 64, a
            // tablice sa ponumerowane od 0 do 63.
            for (int j = 0; j < 8; j++) {
                key56 = setBit(key56, i * 8 + j, isBitSet(key64, PC1[i * 8 + j] - 1));
            }
        }

        byte[] key28Left = new byte[4];
        //tworzymy 2 klucze 28bitowe. Ze wzgledu, ze 28%4!= 0 to musielismy upakowac bity do tablic de facto 32bitowych
        for (int i = 0; i < 4; i ++) {
            for (int j = 0; j < 8; j ++) {
                if (i * 8 + j < 28) {
                    key28Left = setBit(key28Left, i * 8 + j, isBitSet(key56, i * 8 + j));
                }
            }
        }

        byte[] key28Right = new byte[4];

        for (int i = 3; i < 7; i++) {
            for (int j = 0; j < 8; j++) {
                if (i * 8 + j >= 28) {
                    key28Right = setBit(key28Right, i * 8 + j - 28, isBitSet(key56, i * 8 + j));
                }
            }
        }
        //generowanie kluczy 48 bitowych
        for (int i = 0; i < 16; i++) { //1 iteracja - 1 klucz 48 bitowy
            for (int j = 0; j < LeftShifts[i]; j++) { //LeftShifts przechowuje ilosc przesuniec bitowych wymaganych przez algorytm
                key28Left = circularLeftShift(key28Left, 28);
                key28Right = circularLeftShift(key28Right, 28);
            }
            for (int j = 0; j < 28; j++) { //zlaczenie polowek w danej iteracji
                key56 = setBit(key56, j, isBitSet(key28Left, j));
                key56 = setBit(key56, j + 28, isBitSet(key28Right, j));
            }
            /*
            for (int j = 0; j < 6; j++) {
                for (int k = 0; k < 8; k ++) {
                    System.out.println(String.valueOf(i) + " " + String.valueOf(j) + " " + String.valueOf(k) + " ");
                    int index = PC2[k * 8 + j] - 1;
                    boolean bitToSet;
                    if(index < 24) {
                        bitToSet = isBitSet(key28Left, index);
                    } else {
                        bitToSet = isBitSet(key28Right, index);
                    }
                    key48 = setBit(key48,j * 8 + k , bitToSet);
                }
            }*/
            for (int j = 0; j < 48; j++) { //przerobienie klucza 56bitowego na klucz 48bitowy analogicznie jak wczesniej sie zmienialo
                //klucz 64bitowy na 56bitowy, ale tu musimy wykorzystac tablice PC2, zamiast PC1
                subKeys[i]= setBit(subKeys[i], j, isBitSet(key56, PC2[j] - 1));
            }
            //System.out.println("CD" + String.valueOf(i + 1) + ":");
            //printBits(subKeys[i]);
        }
    }

    public byte[] XOR (byte[] bytes1, byte[] bytes2) {
        int length = bytes1.length;
        byte [] xored = new byte[length];
        for (int i = 0; i < length; i++) {
            for (int j = 0; j < 8; j++) {
                boolean bitToSet;
                if (isBitSet(bytes1, i * 8 + j) == isBitSet(bytes2, i * 8 + j)) {
                    bitToSet = false;
                } else {
                    bitToSet = true;
                }
                xored = setBit(xored, i * 8 + j, bitToSet);
            }
        }
        return xored;
    }

    public byte[] FeistelFunction(byte[] message32, byte[] key) {
        byte[] feistel = new byte[6];
        for (int i = 0; i < 6; i ++) {
            for (int j = 0; j < 8; j++) {
                feistel = setBit(feistel, i * 8 + j, isBitSet(message32, EBitSelectionTable[i * 8 + j] - 1));
            }
        }
        //printBits(feistel);
        //byte[] xored = new byte[6];
        byte[] xored = XOR(feistel, key);
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 8; j++) {
                feistel = setBit(feistel, i * 8 + j, isBitSet(xored, i * 8 + j));
            }
        }
        printBits(feistel);
        //to be continued sboxes
        return feistel;
    }

    public byte[] encoding(byte[] partialMessage) { //zakodowanie wiadomosci poczatkowej
        byte [] ip = new byte[8];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ip = setBit(ip, i * 8 + j, isBitSet(partialMessage, initPermutation[i * 8 + j] - 1));
            }
        }
        printBits(ip);
        byte [] ipLeft = new byte[4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                ipLeft = setBit(ipLeft, i * 8 + j, isBitSet(ip, i * 8 + j));
            }
        }
        printBits(ipLeft);
        byte [] ipRight = new byte[4];
        for (int i = 4; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ipRight = setBit(ipRight, i * 8 + j - 32, isBitSet(ip, i * 8 + j));
            }
        }
        printBits(ipRight);

        for (int i = 0; i < 16; i++) {
            //to be continued, Feistel required
        }

        return ip;
    }


    //konwertuje tablicę bajtów na ciąg znaków w systemie heksadecymalnym
    public static String bytesToHex(byte bytes[])
    {
        byte rawData[] = bytes;
        StringBuilder hexText = new StringBuilder();
        String initialHex = null;
        int initHexLength = 0;

        for (int i = 0; i < rawData.length; i++)
        {
            int positiveValue = rawData[i] & 0x000000FF;
            initialHex = Integer.toHexString(positiveValue);
            initHexLength = initialHex.length();
            while (initHexLength++ < 2)
            {
                hexText.append("0");
            }
            hexText.append(initialHex);
        }
        return hexText.toString();
    }

    //konwertuje ciąg znaków w systemie heksadecymalnym na tablicę bajtów
    public static byte[] hexToBytes(String tekst)
    {
        if (tekst == null) { return null;}
        else if (tekst.length() < 2) { return null;}
        else { if (tekst.length()%2!=0)tekst+='0';
            int dl = tekst.length() / 2;
            byte[] wynik = new byte[dl];
            for (int i = 0; i < dl; i++)
            { try{
                wynik[i] = (byte) Integer.parseInt(tekst.substring(i * 2, i * 2 + 2), 16);
            }catch(NumberFormatException e){
                JOptionPane.showMessageDialog(null, "Problem z przekonwertowaniem HEX->BYTE.\n Sprawdź wprowadzone dane.", "Problem z przekonwertowaniem HEX->BYTE", JOptionPane.ERROR_MESSAGE); }
            }
            return wynik;
        }
    }
}
