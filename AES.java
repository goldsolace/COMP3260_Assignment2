/**
 * Implementation of 10 Round 128 bit AES Encryption for single 128 bit blocks.
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 12-05-2019
 */

// TODO: verify encryption results with avalanche effect implemented (verified without)
// TODO: inverse methods and decryption (methods designed to handle inverse
// operations when passed the inverse boolean as true)

public class AES
{
    private Data data = new Data();

    /**
     * Encrypt plaintext.
     *
     * @param cryptoTriplet object holding plaintext and key
     * @param version       specifies which version of AES to run
     */
    public void encrypt(CryptoTriplet cryptoTriplet, int version)
    {
        // Pre-processing

        // Initialize the state array with the block data (plaintext).
        int[] state = Utility.byteArrToIntArr(cryptoTriplet.getPlaintext());

        // 1. Key Expansion:
        // Derive the set of round keys from the cipher key.
        int[] intKey = Utility.byteArrToIntArr(cryptoTriplet.getKey());
        int[] roundKey = Utility.convertArray(expandKey(intKey));

        // 2. Initial Round:
        // Add the initial round key to the starting state array.
        addRoundKey(state, roundKey, 0);

        // 3. Rounds:
        //ROUND 1-9: Perform nine rounds of state manipulation.
        for (int round = 0; round < 9; round++)
        {
            if (version != 1)
                state = substituteBytes(state, false);

            if (version != 2)
                state = shiftRows(state, false);

            if (version != 3)
                state = mixColumns(state, false);

            if (version != 4)
                addRoundKey(state, roundKey, round + 1);

            // Store intermediate state for current version and round
            cryptoTriplet.setIntermediateState(Utility.intArrToByteArr(state), version, round);
        }

        // 4. Final Round
        //ROUND 10 - Perform the tenth and final round of state manipulation.
        if (version != 1)
            state = substituteBytes(state, false);
        if (version != 2)
            state = shiftRows(state, false);
        if (version != 4)
            addRoundKey(state, roundKey, 10);

        byte[] cipherText = Utility.intArrToByteArr(state);
        // Store intermediate state for current version and round
        cryptoTriplet.setIntermediateState(Utility.intArrToByteArr(state), version, 9);
        // Store cipher text in CryptoTriplet
        cryptoTriplet.setCiphertext(cipherText, version);
    }

    /**
     * Decrypt ciphertext.
     *
     * @param cryptoTriplet object holding ciphertext and key
     */
    public void decrypt(CryptoTriplet cryptoTriplet)
    {
        int[] state = Utility.byteArrToIntArr(cryptoTriplet.getCiphertext());

        // Expand key
        int[] intKey = Utility.byteArrToIntArr(cryptoTriplet.getKey());
        int[] roundKey = Utility.convertArray(expandKey(intKey));
        Utility.reverseIntArray(roundKey);

        // Add the initial round key to the starting state array.
        addRoundKey(state, roundKey, 0);

        //ROUND 1-9: Perform nine rounds of state manipulation.
        for (int round = 0; round < 9; round++)
        {
            state = shiftRows(state, true);
            state = substituteBytes(state, true);
            addRoundKey(state, roundKey, round + 1);
            state = mixColumns(state, true);
        }

        //ROUND 10 - Perform the tenth and final round of state manipulation.
        state = shiftRows(state, true);
        state = substituteBytes(state, true);
        addRoundKey(state, roundKey, 10);

        cryptoTriplet.setPlaintext(Utility.intArrToByteArr(state));
    }

    /**
     * Substitute bytes.
     *
     * @param state   current state of plaintext/ciphertext during
     *                encryption/decryption
     * @param inverse specifies whether or not to run inverse method
     */
    private int[] substituteBytes(int[] state, boolean inverse)
    {
        //  uses one table of 16x16 bytes containing a
        // permutation of all 256 8-bit values
        // use the inverted sbox if performing an inverse
        // substituteBytes operation
        char[] sbox = inverse ? data.getInvertedSbox() : data.getSbox();
        //  each byte of state is replaced by byte in row (left
        // 4-bits) & column (right 4-bits)
        //  eg. byte {95} is replaced by row 9 col 5 byte
        //  which is the value {2A}
        //  S-box is constructed using a defined
        // transformation of the values in GF(2^8)
        //  designed to be resistant to all known attacks
        for (int i = 0; i < 16; i++)
            state[i] = (int) sbox[state[i]];

        // reutrn the modifid state contents
        return state;

    }

    /**
     * Shift rows.
     *
     * @param state   current state of plaintext/ciphertext during
     *                encryption/decryption
     * @param inverse specifies whether or not to run inverse method
     */
    private int[] shiftRows(int[] state, boolean inverse)
    {
        int[] temp = new int[16];

        // -1 for right shift, 1 for left shift
        int direction = inverse ? -1 : 1;

        // For rows x columns (4x4 bytes)
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                int index = i * 4 + j;
                // First row unchanged
                if (j % 4 == 0)
                    temp[index] = state[index];
                else
                {
                    // Shift ith row by i bytes in direction
                    temp[index] = state[Math.floorMod((index + j * direction * 4), 16)];
                }
            }
        }
        /*
        // copy shift values into temp array
        temp[0] = state[0];
        temp[1] = state[5];
        temp[2] = state[10];
        temp[3] = state[15];

        temp[4] = state[4];
        temp[5] = state[9];
        temp[6] = state[14];
        temp[7] = state[3];

        temp[8] = state[8];
        temp[9] = state[13];
        temp[10] = state[2];
        temp[11] = state[7];

        temp[12] = state[12];
        temp[13] = state[1];
        temp[14] = state[6];
        temp[15] = state[11];*/

        return temp;
    }

    /**
     * Mix columns.
     *
     * @param state   current state of plaintext/ciphertext during
     *                encryption/decryption
     * @param inverse specifies whether or not to run inverse method
     */
    private int[] mixColumns(int[] state, boolean inverse)
    {
        //  each column is processed separately
        //
        //  each byte is replaced by a value dependent
        // on all 4 bytes in the column
        //  effectively a matrix multiplication in
        // GF(28) using irreducible polynomial
        // m(x) =x^8+x^4+x^3+x+1

        // (see graph)

        //  can express each col as 4 equations
        // 	 to derive each new byte in col
        //  decryption requires use of inverse matrix
        // 	 with larger coefficients, hence a little harder
        //  have an alternate characterisation
        // 	 each column a 4-term polynomial
        // 	 with coefficients in GF(2^8)
        // 	 and polynomials multiplied modulo (x^4+1)
        //

        Data data = new Data();
        int[] mul2 = data.getMul2();
        int[] mul3 = data.getMul3();
        int[] mul9 = data.getMul9();
        int[] mul13 = data.getMul13();
        int[] mul14 = data.getMul14();

        int[] temp = new int[16];

        temp[0] = (mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
        temp[1] = (state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
        temp[2] = (state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
        temp[3] = (mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);
        temp[4] = (mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
        temp[5] = (state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
        temp[6] = (state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
        temp[7] = (mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);
        temp[8] = (mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
        temp[9] = (state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
        temp[10] = (state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
        temp[11] = (mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);
        temp[12] = (mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
        temp[13] = (state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
        temp[14] = (state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
        temp[15] = (mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

        for (int i = 0; i < 16; i++)
            state[i] = temp[i];

        return state;
    }

    /**
     * Add round key.
     * XOR each byte of round key and state table
     *
     * @param state    current state of plaintext/ciphertext during
     *                 encryption/decryption
     * @param roundKey expanded key
     * @param round    current round number of encryption/decryption
     */
    private void addRoundKey(int[] state, int[] roundKey, int round)
    {
        for (int i = 0; i < state.length; i++)
            state[i] ^= roundKey[16 * round + i];
    }

    /**
     * Expand key into set of round keys.
     *  takes 128-bit (16-byte) key and expands into array
     * of 44 32-bit words
     *
     * @param key set of bytes containing original key
     * @return double array of expanded key
     */
    private int[][] expandKey(int[] key)
    {
        int[] Rcon = {0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
        int Nr = 10;
        int Nk = 4;
        int Nb = 4; // for 128 bit key
        int[] temp; // temporary variable to store a word
        int i = 0;
        int[][] exKey = new int[44][4]; // expanded key

        //  start by copying key into first 4 words (16 bytes)
        while (i < Nk)
        {
            exKey[i][0] = key[4 * i];
            exKey[i][1] = key[4 * i + 1];
            exKey[i][2] = key[4 * i + 2];
            exKey[i][3] = key[4 * i + 3];
            i++;
        }
        i = Nk;

        //  then loop creating words that depend on values in
        // previous & 4 places back
        while (i < Nb * (Nr + 1))
        {
            temp = exKey[i - 1];
            //  every 4th has S-box + rotate + XOR round constant on
            // previous before XOR together
            if (i % 4 == 0)        // xor each byte of word
            {
                temp = RotWord(temp);
                // System.out.print("	After RotWord  ");
                // printByte(temp);

                SubWord(temp);

                // System.out.print("	After Subword  ");
                // printByte(temp);

                temp[0] = temp[0] ^ Rcon[i / Nk];

                // System.out.print("	After XOR with Rcon ");
                // printByte(temp);

            } else if (Nk > 6 && i % Nk == 4)
            {
                temp = SubWord(temp);
            }

            //  in 3 of 4 cases just XOR these together
            for (int j = 0; j < 4; j++)
                exKey[i][j] = exKey[i - Nk][j] ^ temp[j];

            // printByte(exKey[i]);
            // System.out.println();

            i++;
        }
        return exKey;
    }

    /**
     * Sub a word with the sbox.
     * takes a four-byte input word and applies the S-box
     * to each of the four bytes to produce an output word.
     *
     * @param word
     * @return sbox substituted word
     */
    private int[] SubWord(int[] word)
    {
        Data data = new Data();
        char[] sbox = data.getSbox();

        for (int i = 0; i < word.length; i++)
        {
            word[i] = sbox[word[i]];
        }
        return word;
    }

    /**
     * Rotate word.
     * takes a word [a0,a1,a2,a3] as input, performs a cyclic
     * permutation, and returns the word [a1,a2,a3,a0].
     *
     * @param word
     * @return rotated word
     */
    private int[] RotWord(int[] word)
    {
        return new int[]{word[1], word[2], word[3], word[0]};
    }
}
