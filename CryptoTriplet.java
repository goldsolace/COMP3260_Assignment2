/**
 * Cryptographic key, plaintext, ciphertext triplets
 * It also has the ability to store the AES version, round number and intermediate results
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 17-04-2019
 */

public class CryptoTriplet {
    private byte[] key;
    private byte[] plaintext;
    private byte[] ciphertext;
    private final byte[][][] intermediateResults;

    public CryptoTriplet(byte[] key, byte[] plaintext, byte[] ciphertext) {
        this.key = key;
        this.plaintext = plaintext;
        this.ciphertext = ciphertext;
        intermediateResults = new byte[Application.NUM_VERSIONS][Application.NUM_ROUNDS][];
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getPlaintext() {
        return plaintext;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[][][] getIntermediateResults() {
        return intermediateResults;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public void setPlaintext(byte[] plaintext) {
        this.plaintext = plaintext;
    }

    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext = ciphertext;
    }
}