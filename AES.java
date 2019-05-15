/**
 * Implementation of 10 Round 128 bit AES Encryption for single 128 bit blocks.
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 15-05-2019
 */

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

        int round = 0;

        // 2. Initial Round:
        // Add the initial round key to the starting state array.
        addRoundKey(state, roundKey, round);

        // 3. Rounds:
        //ROUND 1-9: Perform nine rounds of state manipulation.
        while (round++ < 9)
        {
            if (version != 1)
                state = substituteBytes(state, false);

            if (version != 2)
                state = shiftRows(state, false);

            if (version != 3)
                state = mixColumns(state, false);

            if (version != 4)
                addRoundKey(state, roundKey, round);

            // Store intermediate state for current version and round
            cryptoTriplet.setIntermediateState(Utility.intArrToByteArr(state), version, round - 1);
        }

        // 4. Final Round
        //ROUND 10 - Perform the tenth and final round of state manipulation.
        if (version != 1)
            state = substituteBytes(state, false);
        if (version != 2)
            state = shiftRows(state, false);
        if (version != 4)
            addRoundKey(state, roundKey, round);

        byte[] cipherText = Utility.intArrToByteArr(state);
        // Store intermediate state for current version and round
        cryptoTriplet.setIntermediateState(Utility.intArrToByteArr(state), version, round - 1);
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

        int round = 10;

        // Add the initial round key to the starting state array.
        addRoundKey(state, roundKey, round);

        //ROUND 1-9: Perform nine rounds of state manipulation.
        while (round-- > 1)
        {
            state = shiftRows(state, true);
            state = substituteBytes(state, true);
            addRoundKey(state, roundKey, round);
            state = mixColumns(state, true);
        }

        //ROUND 10 - Perform the tenth and final round of state manipulation.
        state = shiftRows(state, true);
        state = substituteBytes(state, true);
        addRoundKey(state, roundKey, round);

        cryptoTriplet.setPlaintext(Utility.intArrToByteArr(state));
    }

    /**
     * Substitute bytes.
     * Uses 16x16 table of bytes containing a permutation of all 256 8-bit values
     * Use the inverted sbox if performing an inverse substituteBytes operation
     *
     * @param state   current state of plaintext/ciphertext during
     *                encryption/decryption
     * @param inverse specifies whether or not to run inverse method
     */
    private int[] substituteBytes(int[] state, boolean inverse)
    {
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
        return temp;
    }

    /**
     * Mix columns.
     *
     * Columns processed separately with each byte replaced by a value dependent
     * on all 4 bytes in the column, effectively a matrix multiplication in
     * GF(28) using irreducible polynomial m(x) =x^8+x^4+x^3+x+1.
     * Express each col as 4 equations to derive each new byte in col.
     * Decryption requires use of inverse matrix with larger coefficients, hence a little harder
     * Each column a 4-term polynomial with coefficients in GF(2^8) and polynomials multiplied modulo (x^4+1)
     *
     * @param state   current state of plaintext/ciphertext during
     *                encryption/decryption
     * @param inverse specifies whether or not to run inverse method
     */
    private int[] mixColumns(int[] state, boolean inverse)
    {
	// retrieve lookup tables
        int[] mul2 = data.getMul2();
        int[] mul3 = data.getMul3();
        int[] mul9 = data.getMul9();
        int[] mul11 = data.getMul11();
        int[] mul13 = data.getMul13();
        int[] mul14 = data.getMul14();

        int[] temp = new int[16];

        // For each byte
        for (int i = 0; i < 16; i++)
        {
            // Process in blocks of 4 bytes (starting at 0, 4, 8, 12)
	    // e.g.
            // i = 1; j = 0 (0 - 1 mod 4 = 3 state[1]
            //        j = 1 (1 - 1 mod 4 = 0 mul2[state[1]]
            //        j = 2 (2 - 1 mod 4 = 1 mul3[state[1]]
            //        j = 3 (3 - 1 mod 4 = 2 state[1]
            // temp[1] =  state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]
            int start = i - i % 4;
            for (int j = start; j < start + 4; j++)
            {
                // Which multiplication table
                int table = Math.floorMod((j - i), 4);
                if (!inverse)
                {
                    switch (table)
                    {
                        case 0:
                            // XOR for addition
                            temp[i] ^= mul2[state[j]];
                            break;
                        case 1:
                            temp[i] ^= mul3[state[j]];
                            break;
                        default:
                            temp[i] ^= state[j];
                            break;
                    }
                }
                //Inverse Mix Columns
                else
                {
                    switch (table)
                    {
                        case 0:
                            temp[i] ^= mul14[state[j]];
                            break;
                        case 1:
                            temp[i] ^= mul11[state[j]];
                            break;
                        case 2:
                            temp[i] ^= mul13[state[j]];
                            break;
                        case 3:
                            temp[i] ^= mul9[state[j]];
                            break;
                    }
                }
            }
        }
        return temp;
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
     * Takes 128-bit (16-byte) key and expands into array
     * of 44 32-bit words
     *
     * @param key set of bytes containing original key
     * @return double array of expanded key
     */
    private int[][] expandKey(int[] key)
    {
        int[] Rcon = {0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
        int Nr = 10; // number of rounds
        int Nk = 4; // number of 32 bit words comprising the cipher key
        int Nb = 4; // number of columns (32-bit words) comprising the state
        int[] temp; // temporary variable to store a word
        int i = 0;
        int[][] exKey = new int[44][4]; // expanded key

        // Start by copying key into first 4 words (16 bytes)
        while (i < Nk)
        {
            exKey[i][0] = key[4 * i];
            exKey[i][1] = key[4 * i + 1];
            exKey[i][2] = key[4 * i + 2];
            exKey[i][3] = key[4 * i + 3];
            i++;
        }
        i = Nk;

        // Loop creating words that depend on values in previous & 4 places back
        while (i < Nb * (Nr + 1))
        {
            temp = exKey[i - 1];
            //  every 4th has S-box + rotate + XOR round constant on
            // previous before XOR together
            if (i % 4 == 0)        // xor each byte of word
            {
                temp = RotWord(temp);

                SubWord(temp);

                temp[0] = temp[0] ^ Rcon[i / Nk];

            } else if (Nk > 6 && i % Nk == 4)
            {
                temp = SubWord(temp);
            }

            //  in 3 of 4 cases just XOR these together
            for (int j = 0; j < 4; j++)
                exKey[i][j] = exKey[i - Nk][j] ^ temp[j];

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
        char[] sbox = data.getSbox();

        for (int i = 0; i < word.length; i++)
        {
            word[i] = sbox[word[i]];	// replace word with word at corresponding index of S-Box
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
