/**
 * Class Description
 * 
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 11-05-2019
 */

// TODO: Read this v
// all core AES methods are working as tested on byte/hex values
// the readBinary method was designed to be used to read a binary string in
// the format of the relevant bytewise values
// NOTE: testing so far has been done on an external file as I have not yet
// got myself familiar with using Application.java
//
// If you encounter any problems testing with the "byte" values then change them
// all to integer values as that was what used when successfully testing each
// method
// TODO: test from Application
// TODO: verify results after a full encryption
// TODO: inverse methods and decryption (methods designed to handle inverse
// operations when passed the inverse boolean as true)

public class AES {
	static Data data = new Data();

	public AES() {
	}

	public byte[] readBinary(String plaintext)
	{
		int Bit = 0;
		byte[] state = new byte[16];
		for (int j = 0; j < 16; j++)
		{
			state[j] = 0;
			for (int i = 0; i < 8; i++)
			{
				System.out.print("char "+plaintext.charAt(j*8+i));
				if (i % 8 == 0)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 7);
				if (i % 8 == 1)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 6);
				if (i % 8 == 2)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 5);
				if (i % 8 == 3)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 4);
				if (i % 8 == 4)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 3);
				if (i % 8 == 5)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 2);
				if (i % 8 == 6)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 1);
				if (i % 8 == 7)
					Bit = (int)Math.pow(Character.getNumericValue(plaintext.charAt(j*8+i))*2, 0);
				System.out.println(" value " + Bit);
				state[j] += Bit;
			}
		}
		return state;
	}

	// Input: 128 bit plaintext block and 128 bit key
	// Output: 128 bit cipertext block
	public void encrypt(CryptoTriplet cryptoTriplet, int version) // Jeremiah
	{
		// Pre-processing

		// Initialize the state array with the block data (plaintext).
		byte state[] = cryptoTriplet.getPlaintext();

		// 1. Key Expansion:
		// Derive the set of round keys from the cipher key.
		// byte[] roundKey = new byte[16];
		
		// used this for testing expandKey
		//String key = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";

		// read in 16 byte key, cast to int
		byte[] byteKey = cryptoTriplet.getKey();
		int[] intKey = new int[byteKey.length];
		for (int i = 0; i < byteKey.length; i++)
			intKey[i] = Byte.toUnsignedInt(byteKey[i]);

		// Create round key...
		int[] roundKey = convertArray(expandKey(intKey));

		// 2. Initial Round:
		// Add the initial round key to the starting state array.
		addRoundKey(state, roundKey);

		// 3. Rounds:
		//ROUND 1-9: Perform nine rounds of state manipulation.
		for (int i = 0; i < 9; i++)
		{
			if (version != 1)
				state = substituteBytes(state, false);
			if (version != 2)
				state = shiftRows(state, false);
			if (version != 3)
				state = mixColumns(state, false);
			if (version != 4)
				addRoundKey(state, roundKey);
		}

		// 4. Final Round
		//ROUND 10 - Perform the tenth and final round of state manipulation.
		if (version != 1)
			state = substituteBytes(state, false);
		if (version != 2)
			state = shiftRows(state, false);
		if (version != 4)
			addRoundKey(state, roundKey);

		// Copy the final state array out as the encrypted data (ciphertext).

		// return encrypted data (ciphertext)
	}

	// Input: 128 bit cipertext block and 128 bit key
	// Output: 128 bit plaintext
	public byte[] decrypt(CryptoTriplet cryptoTriplet, int version)
	{
		byte[] state = cryptoTriplet.getCiphertext();

		// expand key
		byte[] key = cryptoTriplet.getKey();
		int[] roundKey = new int[16];
		// expandKey(key); // TODO
		//ROUND 1
		if (version != 2)
			// Inverse shift rows
			state = shiftRows(state, true);
		if (version != 1)
			// Inverse sub bytes
			state = substituteBytes(state, true);
		if (version != 4)
			// Add round key
			addRoundKey(state, roundKey);
		if (version != 3)
			// Inverse mix columns
			state = mixColumns(state, true);
		//ROUND 2-10
		for (int i = 0; i < 9; i++)
		{
			if (version != 2)
				// Inverse shift rows
				state = shiftRows(state, true);
			if (version != 1)
				// Inverse sub bytes
				state = substituteBytes(state, true);
			if (version != 4)
				// Add Round Key
				addRoundKey(state, roundKey);
		}

		return cryptoTriplet.getPlaintext();
	}

	// a simple substitution of each byte
	private byte[] substituteBytes(byte[] state, boolean inverse)
	{
		char[] sbox = data.getSbox();
		//  uses one table of 16x16 bytes containing a
		// permutation of all 256 8-bit values
		// use the inverted sbox if performing an inverse
		// substituteBytes operation
		if (inverse)
			sbox = data.getInvertedSbox();
		//  each byte of state is replaced by byte in row (left
		// 4-bits) & column (right 4-bits)
		//  eg. byte {95} is replaced by row 9 col 5 byte
		//  which is the value {2A}
		//  S-box is constructed using a defined
		// transformation of the values in GF(2^8)
		//  designed to be resistant to all known attacks
		for (int i = 0; i < 16; i++)
			state[i] = (byte)sbox[state[i]];

		// reutrn the modifid state contents
		return state;

	}

	private byte[] shiftRows(byte[] state, boolean inverse)
	{
		byte temp[] = new byte[16];

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
		temp[15] = state[11];

		// copy temp array into state array
		for (int i = 0; i < 16; i++)
			state[i] = temp[i];

		return state;
	}


	private byte[] mixColumns(byte[] state, boolean inverse) // Jeremiah
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

		temp[0] = (mul2[state[0]]^mul3[state[1]]^state[2]^state[3]);
		temp[1] = (state[0]^mul2[state[1]]^mul3[state[2]]^state[3]);
		temp[2] = (state[0]^state[1]^mul2[state[2]]^mul3[state[3]]);
		temp[3] = (mul3[state[0]]^state[1]^state[2]^mul2[state[3]]);
		temp[4] = (mul2[state[4]]^mul3[state[5]]^state[6]^state[7]);
		temp[5] = (state[4]^mul2[state[5]]^mul3[state[6]]^state[7]);
		temp[6] = (state[4]^state[5]^mul2[state[6]]^mul3[state[7]]);
		temp[7] = (mul3[state[4]]^state[5]^state[6]^mul2[state[7]]);
		temp[8] = (mul2[state[8]]^mul3[state[9]]^state[10]^state[11]);
		temp[9] = (state[8]^mul2[state[9]]^mul3[state[10]]^state[11]);
		temp[10] = (state[8]^state[9]^mul2[state[10]]^mul3[state[11]]);
		temp[11] = (mul3[state[8]]^state[9]^state[10]^mul2[state[11]]);
		temp[12] = (mul2[state[12]]^mul3[state[13]]^state[14]^state[15]);
		temp[13] = (state[12]^mul2[state[13]]^mul3[state[14]]^state[15]);
		temp[14] = (state[12]^state[13]^mul2[state[14]]^mul3[state[15]]);
		temp[15] = (mul3[state[12]]^state[13]^state[14]^mul2[state[15]]);

		for (int i = 0; i < 16; i++)
			state[i] = (byte)temp[i];

		return state;
	}

	// XOR each byte of round key and state table
	private void addRoundKey(byte[] state, int roundKey[])
	{
		for (int i = 0; i < state.length; i++)
			state[i] ^= roundKey[i];
	}

	//  takes 128-bit (16-byte) key and expands into array
	// of 44 32-bit words
	private int[][] expandKey(int key[])//, int exKey[], int Nk, int Nb, int Nr)//(byte key[4*Nk], word exKey[Nb*(nr+1)], Nk)
	{

		int[] Rcon = {0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
		int Nr = 10; int Nk = 4; int Nb = 4; 	// for 128 bit key
		int temp[] = new int[4];		// temporary variable to store a word
		int i = 0;
		int exKey[][] = new int[44][4];		// expanded key

		//  start by copying key into first 4 words (16 bytes)
		while(i < Nk)
		{
			exKey[i][0] = key[4*i];
			exKey[i][1] = key[4*i+1];
			exKey[i][2] = key[4*i+2];
			exKey[i][3] = key[4*i+3];
			i++;
		}
		i = Nk;

		//  then loop creating words that depend on values in
		// previous & 4 places back
		while (i < Nb * (Nr+1))
		{
			temp = exKey[i-1];
			//  every 4th has S-box + rotate + XOR round constant on
			// previous before XOR together
			if (i % 4 == 0)		// xor each byte of word
			{
				temp = RotWord(temp);
				System.out.print("	After RotWord  ");
				printB(temp);

				SubWord(temp);

				System.out.print("	After Subword  ");
				printB(temp);

				temp[0] = temp[0] ^ Rcon[i/Nk];

				System.out.print("	After XOR with Rcon ");
				printB(temp);
			}
			else if (Nk > 6 && i % Nk == 4)
				temp = SubWord(temp);

			//  in 3 of 4 cases just XOR these together
			for (int j = 0; j < 4; j++)
				exKey[i][j] = exKey[i-Nk][j] ^ temp[j];

			printB(exKey[i]);
			System.out.println();

			i++;
		}
		return exKey;
	}

	// for debugging
	static void printB(int word[])
	{
		System.out.print(Integer.toHexString(word[0]));
		System.out.print(Integer.toHexString(word[1]));
		System.out.print(Integer.toHexString(word[2]));
		System.out.print(Integer.toHexString(word[3]) + "	");
	}



	// takes a four-byte input word and applies the S-box
	// to each of the four bytes to produce an output word.
	private int[] SubWord(int word[])
	{
		Data data = new Data();
		char[] sbox = data.getSbox();

		for (int i = 0; i < word.length; i++)
		{
			word[i] = sbox[word[i]];
		}
		return word;
	}

	// takes a word [a0,a1,a2,a3] as input, performs a cyclic 
	// permutation, and returns the word [a1,a2,a3,a0].
	private int[] RotWord(int word[])
	{
		int[] temp = {word[1], word[2], word[3], word[0]};
		return temp;
	}

	public int[] convertArray(int[][] arr)
	{
		int m = arr.length;
		int n = arr[0].length;
		int[] newArr = new int[m*n+n];//?
		for(int i=0; i<arr.length; i++)
		{
			for(int j=0;j<arr[0].length;j++)
			{
				int position = i*n + j;
				newArr[position] = arr[i][j];
			}
		}
		return newArr;
	}

}
