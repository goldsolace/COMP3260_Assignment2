import java.util.HashMap;

/**
 * Cryptographic key, plaintext, ciphertext triplets
 * It also has the ability to store the AES version, round number and intermediate results
 * 
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 17-04-2019
 */

public class CryptoTriplet<K, P, C> {
	private K key;
	private P plaintext;
	private C ciphertext;
	private final String[][] intermediateResults;

	public CryptoTriplet(K key, P plaintext, C ciphertext) {
		this.key = key;
		this.plaintext = plaintext;
		this.ciphertext = ciphertext;
		// 2D Matrix to store intermediate results of each round for each version
		// getIntermediateResults
		intermediateResults = new String[Application.NUM_ROUNDS][Application.NUM_VERSIONS];
	}

	public K getKey() { return key; }
	public P getPlaintext() { return plaintext; }
	public C getCiphertext() { return ciphertext; }
	public String[][] getIntermediateResults() { return intermediateResults; }

	public void setKey(K key) { this.key = key; }
	public void setPlaintext(P plaintext) { this.plaintext = plaintext; }
	public void setCiphertext(C ciphertext) { this.ciphertext = ciphertext; }
}