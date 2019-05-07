import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Class Description
 * 
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 17-04-2019
 */

// DUE: 4/05/2019
public class AES {
	
	public AES() {
	}

	// Input: 128 bit plaintext block and 128 bit key
	// Output: 128 bit cipertext block
	public void encrypt(CryptoTriplet<String, String, String> cyptoTriplet, int version) // Jeremiah
	{
		// 1. Key Expansion:
		// Derive the set of round keys from the cipher key.
		expandKey();

		// 2. Initial Round:
		// Initialize the state array with the block data (plaintext).
		// Add the initial round key to the starting state array.

		// 3. Rounds:
		//ROUND 1-9: Perform nine rounds of state manipulation.
		for (int i = 0; i < 9; i++)
		{
			if (version != 1)
				substituteBytes();
			if (version != 2)
				shiftRows();
			if (version != 3)
				mixColumns();

			if (version != 4)
				addRoundKey();
		}
		
		// 4. Final Round
		//ROUND 10 - Perform the tenth and final round of state manipulation.
		if (version != 1)
			substituteBytes();
		if (version != 2)
			shiftRows();
		if (version != 4)
			addRoundKey();

		// Copy the final state array out as the encrypted data (ciphertext).
		
		// return encrypted data (ciphertext)
	}

	// Input: 128 bit cipertext block and 128 bit key
	// Output: 128 bit plaintext
	public void decrypt(CryptoTriplet<String, String, String> cyptoTriplet, int version) // Jeremiah
	{
		//ROUND 1
		if (version != 2)
		{// Inverse shift rows
		}
		if (version != 1)
		{// Inverse sub bytes
		}
		if (version != 4)
		{// Add round key
		}
		if (version != 3)
		{// Inverse mix columns
		}
		
		//ROUND 2-10
		for (int i = 0; i < 9; i++)
		{
			if (version != 2)
			{// Inaerse shift rows
			}
			if (version != 1)
			{// Inverse sub bytes
			}
			if (version != 4)
			{// Add Round Key
			}
		}

		// return plaintext
	}

	private void substituteBytes() // Jeremiah
	{
	// a simple substitution of each byte
	//  uses one table of 16x16 bytes containing a
	// permutation of all 256 8-bit values
	//  each byte of state is replaced by byte in row (left
	// 4-bits) & column (right 4-bits)
	//  eg. byte {95} is replaced by row 9 col 5 byte
	//  which is the value {2A}
	//  S-box is constructed using a defined
	// transformation of the values in GF(2^8)
	//  designed to be resistant to all known attacks
	}

	private void shiftRows() { // Brice
	}

	private void mixColumns() // Jeremiah
	{
	// each column is processed separately
	// each byte is replaced by a value dependent
	// on all 4 bytes in the column
	// effectively a matrix multiplication in
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
	}

	private void addRoundKey() { // Brice
	}

	private void expandKey()
	{

	}
}
