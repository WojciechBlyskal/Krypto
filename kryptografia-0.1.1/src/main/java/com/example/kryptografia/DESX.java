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

    private byte[] S1 = {
            14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
             0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
             4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
            15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    };
    private byte[] S2 = {
            15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    };
    private byte[] S3 = {
            10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    };
    private byte[] S4 = {
             7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
             3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    };
    private byte[] S5 = {
             2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
             4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    };
    private byte[] S6 = {
            12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
            10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
             9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    };
    private byte[] S7 = {
             4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
            13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    };
    private byte[] S8 = {
            13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
             1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    };
    private byte[] permutationP = {
            16,  7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26,  5, 18, 31, 10,
             2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
    };

    private byte[] endPermutation = {
            40,  8, 48, 16, 56, 24, 64, 32,
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44,  2, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25
    };

    private byte[] keyInternal;

    private byte[] keyExternal;

    private byte[] keyDes;

    public void setKeyInternal(byte[] keyInt) {
        this.keyInternal = keyInt;
    }

    public void setKeyExternal(byte[] keyExt) {
        this.keyExternal = keyExt;
    }

    public void setKeyDes(byte[] keyDes) {
        this.keyDes = keyDes;
        generate16Keys(keyDes);
    }

    public byte[] getKeyInternal() {
        return keyInternal;
    }

    public byte[] getKeyExternal() {
        return keyExternal;
    }

    public byte[] getKeyDes() {
        return keyDes;
    }

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
            for (int j = 0; j < 48; j++) { //przerobienie klucza 56bitowego na klucz 48bitowy analogicznie jak wczesniej sie zmienialo
                //klucz 64bitowy na 56bitowy, ale tu musimy wykorzystac tablice PC2, zamiast PC1
                subKeys[i]= setBit(subKeys[i], j, isBitSet(key56, PC2[j] - 1));
            }
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

    public byte[] FeistelFunction(byte[] message32, byte[] key) { //funkcja Feistel specyficzna funkcja wymagana przy szyfrowaniu
        byte[] feistel = new byte[6];
        for (int i = 0; i < 6; i ++) {  //przepisujemy bity z wiadomosci zgodnie z kolejnoscia w EBitSelectionTable(bo wymaga tego algorytm)
            // rozszerzajac ja do 48bitow, by pasowala wielkoscia do klucza.
            for (int j = 0; j < 8; j++) {
                feistel = setBit(feistel, i * 8 + j, isBitSet(message32, EBitSelectionTable[i * 8 + j] - 1));
            }
        }
        byte[] xored = XOR(feistel, key);
        for (int i = 0; i < 6; i++) { //wykonujemy operacje xor miedzy wiadomoscia po przestawieniu bitow i kluczem(1 z 16)
            for (int j = 0; j < 8; j++) {
                feistel = setBit(feistel, i * 8 + j, isBitSet(xored, i * 8 + j));
            }
        }

        byte[] beforePermutation = new byte [4]; //zmiena beforePermutation zbierze nam wyniki przekszalcenia 6bitowych czesci wiadomosci sboxami spowrotem w calosc
        for (int i = 0; i < 8; i ++) {  //Szyfrujemy wiadomosc stosujac SBoxy. Dzielimy wiadomosc na 6 bitowe czesci.
            int row = 0;
            int column = 0;
            byte afterbox;
            for (int j = 0; j < 6; j++) {   //W kazdej czesci pierwszy i szosty bit okreslaja wiersz, a bity drugi, trzeci, czwarty, piaty kolumne.
                //np. dla 101010 wskazuje na wiersz 10(traktuj binarnie), czyli na wiersz trzeci i kolumne 0101(traktuj binarnie) szosta.
                switch (j) {
                    case 0:
                        if (isBitSet(feistel, i * 6 + j)) {
                            row = row + 2;
                        }
                        break;
                    case 1:
                        if (isBitSet(feistel, i * 6 + j)) {
                            column = column + 8;
                        }
                        break;
                    case 2:
                        if (isBitSet(feistel, i * 6 + j)) {
                            column = column + 4;
                        }
                        break;
                    case 3:
                        if (isBitSet(feistel, i * 6 + j)) {
                            column = column + 2;
                        }
                        break;
                    case 4:
                        if (isBitSet(feistel, i * 6 + j)) {
                            column = column + 1;
                        }
                        break;
                    case 5:
                        if (isBitSet(feistel, i * 6 + j)) {
                            row = row + 1;
                        }
                        byte[] aux = new byte[1];
                        switch (i) {    //Znajac wiersz i kolumne mozemy okreslic ktory nr bitu w sboxie nas interesuje.
                            //Wyszukujemy w odpowiednim sboxie(dla pierwszej 6bitowej czesci pierwszy sbox itd.) liczbe, ktora jest
                            // w danym wierszu i danej kolumnie. W zaleznosci od tresci wiadomosci sboxy beda zwracaly nam inne liczby.
                            case 0:
                                afterbox = S1[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k, isBitSet(aux, k + 4));
                                }
                                break;
                            case 1:
                                afterbox = S2[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 4, isBitSet(aux, k + 4));
                                }
                                break;
                            case 2:
                                afterbox = S3[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 8, isBitSet(aux, k + 4));
                                }
                                break;
                            case 3:
                                afterbox = S4[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 12, isBitSet(aux, k + 4));
                                }
                                break;
                            case 4:
                                afterbox = S5[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 16, isBitSet(aux, k + 4));
                                }
                                break;
                            case 5:
                                afterbox = S6[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 20, isBitSet(aux, k + 4));
                                }
                                break;
                            case 6:
                                afterbox = S7[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 24, isBitSet(aux, k + 4));
                                }
                                break;
                            case 7:
                                afterbox = S8[row * 16 + column];
                                aux[0] = afterbox;
                                for (int k = 0; k < 4; k++) {
                                    beforePermutation = setBit(beforePermutation, k + 28, isBitSet(aux, k + 4));
                                }
                                break;
                        }
                        break;
                }
            }
        }
        byte[] output = new byte[4];
        for (int i = 0; i < 4; i ++) {  // Dokonujemy permutacji P.
            for (int j = 0; j < 8; j++) {
                output = setBit(output, i * 8 + j, isBitSet(beforePermutation, permutationP[i * 8 + j] - 1));
            }
        }
        return output;
    }

    public byte[] encryption(byte[] partialMessage) { //zakodowanie wiadomosci poczatkowej
        byte [] ip = new byte[8];   //stosujemy na wiadomosci permutacje poczatkowa
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ip = setBit(ip, i * 8 + j, isBitSet(partialMessage, initPermutation[i * 8 + j] - 1));
            }
        }

        byte [] ipLeft = new byte[4];

        for (int i = 0; i < 4; i++) { //dzielimy spermutowana wiadomosc na 2 czesci-L0 i P0(L zero i P zero
            for (int j = 0; j < 8; j++) {
                ipLeft = setBit(ipLeft, i * 8 + j, isBitSet(ip, i * 8 + j));
            }
        }

        byte [] ipRight = new byte[4];
        for (int i = 4; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ipRight = setBit(ipRight, i * 8 + j - 32, isBitSet(ip, i * 8 + j));
            }
        }

        byte[] ipAux = new byte[4]; //wlasciwa czesc algorytmu.
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 4; j++) { //Zapisujemy lewa czesc wiadomosci w zmiennej pomocniczej ipAux.
                for (int k = 0; k < 8; k++) {
                    ipAux = setBit(ipAux, j * 8 + k, isBitSet(ipLeft, j * 8 + k));
                }
            }

            for (int j = 0; j < 4; j++) {// nastepnie nadpisujemy lewa prawa czescia(zgodnie z algorytmem L0 = R1).
                for (int k = 0; k < 8; k++) {
                ipLeft = setBit(ipLeft, j * 8 + k, isBitSet(ipRight, j * 8 + k));
                }
            }
            byte[] aux2;
            aux2 = XOR(ipAux, FeistelFunction(ipLeft, subKeys[i])); // Szykujemy sobie xora w zmiennej aux2 (L0 ^ funkcjaFeistla(R0, Klucz1))
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 8; k++) { // Wykorzystujac, ze wartosc L0 zostala zapisana w ipAux, a to co bylo nam potrzebne z R0
                    //zapisalismy w zmiennej aux2 nadpisujemy ipRight (R0 = L0 ^ funkcjaFeistla(R0, Klucz1))
                    //cala petla(iteratowana przez i) wykona sie az do uzyskania L16 i R16 w sposob analogiczny jak wczesniej
                    //Ln i Rn sa nam potrzebne tylko by uzyskac L16 i R16
                    ipRight = setBit(ipRight, j * 8 + k, isBitSet(aux2, j * 8 + k));
                }
            }
        }
        for (int i = 0; i < 8; i++) { //Skladamy L16 i R16 w calosc, ale algorytm wymaga by ustawic je odwrotnie(R16L16)
            for (int j = 0; j < 8; j++) {
                if (i < 4) {
                    ip = setBit(ip, i * 8 + j, isBitSet(ipRight, i * 8 + j));
                } else {
                    ip = setBit(ip, i * 8 + j, isBitSet(ipLeft, i * 8 + j - 32));
                }
            }
        }
        byte[] encrypted = new byte[8]; //dokonujemy permutacji koncowej
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                encrypted = setBit(encrypted, i * 8 + j, isBitSet(ip, endPermutation[i * 8 + j] - 1));
            }
        }
        return encrypted;
    }

    public byte[] finalencryption (byte[] message) { //czesc ktora nam robi DESX z DES
        int addition = 0;       //przewidujemy, ze wiadomosc moze nie miec idealnie 8 bajtow w zwiazku z czym wydluzamy wiadomosc
        //bajtami zawerajacymi 0, by dlugosc byla podzielna przez 8
        int length = message.length;
        if (length % 8 != 0) {
            addition = 8 - (length % 8);
        }

        int extendedlength = length + addition;
        byte[] extendedmessage = new byte[extendedlength];
        System.arraycopy(message, 0, extendedmessage, 0, length);
        for (int i = length; i < extendedlength; i++) {
            extendedmessage[i] = 0; //douzupełniamy zerami
        }

        byte[] aux = new byte[extendedlength];
        byte[] temp = new byte[8];

        for (int i = 0; i < extendedlength / 8; i++) {  //wlasciwe szyfrowanie
            int startIndex = i * 8;
            System.arraycopy(extendedmessage, startIndex, temp, 0, 8);

            for (int j = 0; j < 8; j++) {   //xorujemy nasza wiadomosc z kluczem internal
                temp[j] = (byte) (temp[j] ^ keyInternal[j]);
            }

            byte[] partialCipher = encryption(temp); //dokonujemy enkrypcji tak jak w zwyklym DESie podajac zxorowana wiadomosc

            for (int j = 0; j < 8; j++) {   //po szyfrowaniu znowu dokonujemy xorowania szyfru ale przez klucz External
                partialCipher[j] = (byte) (partialCipher[j] ^ keyExternal[j]);
            }

            System.arraycopy(partialCipher, 0, aux, startIndex, 8);
        }
        return aux; //zwracamy zaszyfrowana wiadomosc
    }

    public byte[] decryption(byte[] partialMessage) { //praktycznie to samo co encryption, ale kilka rzeczy jest na odwrot
        byte [] ip = new byte[8];   //stosujemy na wiadomosci permutacje poczatkowa
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ip = setBit(ip, i * 8 + j, isBitSet(partialMessage, initPermutation[i * 8 + j] - 1));
            }
        }
        byte [] ipLeft = new byte[4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                ipLeft = setBit(ipLeft, i * 8 + j, isBitSet(ip, i * 8 + j));
            }
        }

        byte [] ipRight = new byte[4];
        for (int i = 4; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ipRight = setBit(ipRight, i * 8 + j - 32, isBitSet(ip, i * 8 + j));
            }
        }

        byte[] ipAux = new byte[4];
        for (int i = 15; i >= 0; i--) { //w odroznieniu od encryption iterujemy od 15 do 0;
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 8; k++) {
                    ipAux = setBit(ipAux, j * 8 + k, isBitSet(ipLeft, j * 8 + k));
                }
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 8; k++) {
                    ipLeft = setBit(ipLeft, j * 8 + k, isBitSet(ipRight, j * 8 + k));
                }
            }
            byte[] aux2;
            aux2 = XOR(ipAux, FeistelFunction(ipLeft, subKeys[i]));
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 8; k++) {
                    ipRight = setBit(ipRight, j * 8 + k, isBitSet(aux2, j * 8 + k));
                }
            }
        }
        for (int i = 0; i < 8; i++) { //Skladamy L0 i R0 w calosc, ale algorytm wymaga by ustawic je odwrotnie(R0L0)
            for (int j = 0; j < 8; j++) {
                if (i < 4) {
                    ip = setBit(ip, i * 8 + j, isBitSet(ipRight, i * 8 + j));
                } else {
                    ip = setBit(ip, i * 8 + j, isBitSet(ipLeft, i * 8 + j - 32));
                }
            }
        }
        byte[] decrypted = new byte[8]; //dokonujemy permutacji koncowej
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                decrypted = setBit(decrypted, i * 8 + j, isBitSet(ip, endPermutation[i * 8 + j] - 1));
            }
        }
        return decrypted;
    }

    public byte[] finalDecryption(byte[] fullMessage) { //praktycznie to samo co finalencryption, ale na odwrot
        //przy dekrypcji nie potrzebujemy dostosowywac do odpowiedniej dlugosci wiadomosci bo enkrypcja juz o nia zadbala
        int length = fullMessage.length;

        byte[] fullCipher = new byte[length];
        byte[] temp = new byte[8];

        for (int i = 0; i < length / 8; i++) {
            int startIndex = i * 8;
            System.arraycopy(fullMessage, startIndex, temp, 0, 8);

            for (int j = 0; j < 8; j++) {  //xorujemy nasz szyfr tym razem z kluczem external
                temp[j] = (byte) (temp[j] ^ keyExternal[j]);
            }

            byte[] partialCipher = decryption(temp); //dokonujemy dekrypcji tak jak w zwyklym DESie podajac zxorowany szyfr

            for (int j = 0; j < 8; j++) {
                partialCipher[j] = (byte) (partialCipher[j] ^ keyInternal[j]); //ponownie xorujemy nasz szyfr tym razem z kluczem internal
            }

            System.arraycopy(partialCipher, 0, fullCipher, startIndex, 8);
        }
        return fullCipher;
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
