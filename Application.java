import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JOptionPane;
import java.util.*;
import java.io.*;

/**
 * Class Description
 * 
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 11-05-2019
 */

public class Application {

	public static final int NUM_VERSIONS = 5;
	public static final int NUM_ROUNDS = 10;
	public static final int KEY_SIZE = 128;


	private boolean isEncryption;
	private File file;
	private StringBuilder output;

	/**
	 * Constructs an Application object from params.
	 *
	 * @param isEncryption true if encryption, false if decryption
	 * @param file file to run application with
	 */
	public Application(boolean isEncryption, File file) {
		this.isEncryption = isEncryption;
		this.file = file;
		output = new StringBuilder();
	}

	/**
	 * Main Method.
	 *
	 * @param args command line arguments
	 */
	public static void main(String[] args) {
		File file = null;
		boolean isEncryption;

		// Get operation and file from command line args or gui file chooser
		try {
			if (args.length > 0) {
				if (args[0].equalsIgnoreCase("--encrypt"))
					isEncryption = true;
				else if (args[0].equalsIgnoreCase("--decrypt"))
					isEncryption = false;
				else
				{
					System.out.println("Please use first arguments '--encrypt' for encryption or '--decrypt' for decryption followed by the input file name.");
					return;

				}
				file = new File(args[1]);
			} else {
				Object[] options = { "Encryption", "Decryption" };
				isEncryption = JOptionPane.showOptionDialog(null, "Operation?", "Please choose an opteration",
					JOptionPane.YES_NO_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, null) == JOptionPane.YES_OPTION;
				JFileChooser fileChooser = new JFileChooser();
				//fileChooser.setFileFilter(new FileNameExtensionFilter("*.txt", "txt"));
				fileChooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION)
					file = fileChooser.getSelectedFile();
			}
			
			// Run the simulation on selected file
			if (file != null) {
				Application app = new Application(isEncryption, file);
				app.run();
			} else {
				System.out.println("Error! Valid file not specified at command line or using file chooser GUI.");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Run the application.
	 */
	public void run() {
		CryptoTriplet<String, String, String> cyptoTriplet = readFile();
		
		if (cyptoTriplet == null) return;

		AES aes = new AES();

		if (isEncryption) {

			List<List<CryptoTriplet<String, String, String>>> results = new ArrayList<>();
			
			long startTime = System.currentTimeMillis();

			// Explore each version of AES (AES0-AES4) on the current orginal cyptroTriplet
			for (int aesVersion = 0; aesVersion < 5; aesVersion++) {
				aes.encrypt(cyptoTriplet, aesVersion);
			}

			for (int i = 0; i < KEY_SIZE; i++) {
				
				// Explore the changing of the ith bit
				String ithKey = swapOneBit(cyptoTriplet.getKey(), i);
				String ithPlaintext = swapOneBit(cyptoTriplet.getPlaintext(), i);

				List<CryptoTriplet<String, String, String>> cyptoTriplets = new ArrayList<>();
				// a) P and Pi under K
				cyptoTriplets.add(new CryptoTriplet<>(cyptoTriplet.getKey(), ithPlaintext, ""));
				// b) P under K and Ki
				cyptoTriplets.add(new CryptoTriplet<>(ithKey, cyptoTriplet.getPlaintext(), ""));

				// Explore each version of AES (AES0-AES4) on each of the current cyptroTriplets
				for (CryptoTriplet<String, String, String> triplet : cyptoTriplets) {
					for (int aesVersion = 0; aesVersion < 5; aesVersion++) {
						aes.encrypt(cyptoTriplet, aesVersion);
					}
				}

				// Store the results
				results.add(cyptoTriplets);
			}
			long runningTime = System.currentTimeMillis() - startTime;
			
			// Perform Avalanche effect analysis
			int[][][] analysis = AvalancheAnalysis(cyptoTriplet, results);
			GenerateEncryptionOutput(cyptoTriplet, analysis, runningTime);
		} else {
			aes.decrypt(cyptoTriplet);

			GenerateDecryptionOutput(cyptoTriplet);
		}

		System.out.println(output.toString());
		writeFile();
	}

	/**
	 * Swaps a specified bit in string of 1s and 0s
	 */
	private String swapOneBit(String s, int bit) {
		if (bit >= s.length()) bit = s.length() - 1;
		char[] characters = s.toCharArray();
		characters[bit]  = characters[bit] == '0' ? '1' : '0';
		return new String(characters);
	}

	/**
	 * Performs avalanche effect analysis on the results and computes the average
	 */
	private int[][][] AvalancheAnalysis(CryptoTriplet<String, String, String> original, List<List<CryptoTriplet<String, String, String>>> results) {
		
		// TODO Analysis
		
		int[][] pAndPiUnderKAverages = new int[Application.NUM_ROUNDS][Application.NUM_VERSIONS];
		int[][] pUnderKAndKiAverages = new int[Application.NUM_ROUNDS][Application.NUM_VERSIONS];

		int[][][] analysis = new int[2][][];
		analysis[0] = pAndPiUnderKAverages;
		analysis[1] = pUnderKAndKiAverages;
		return analysis;
	}

	/**
	 * Appends the formatted result of decryption to output
	 */
	private void GenerateEncryptionOutput(CryptoTriplet<String, String, String> original, int[][][] analysis, long runningTime) {
		output.append("ENCRYPTION").append(System.lineSeparator());
		output.append("Plaintext P: ").append(original.getPlaintext()).append(System.lineSeparator());
		output.append("Key K: ").append(original.getKey()).append(System.lineSeparator());
		output.append("Ciphertext C: ").append(original.getCiphertext()).append(System.lineSeparator());
		output.append("Running time: ").append(runningTime).append("ms").append(System.lineSeparator());
		output.append("Avalanche: ").append(System.lineSeparator());
		output.append("P and Pi under K").append(System.lineSeparator());
		// TODO Rounds/Versions for analysis[0]
		output.append("P under K and Ki").append(System.lineSeparator());
		// TODO Rounds/Versions for analysis[1]


		
	}

	/**
	 * Appends the formatted result of decryption to output
	 */
	private void GenerateDecryptionOutput(CryptoTriplet<String, String, String> result) {
		output.append("DECRYPTION").append(System.lineSeparator());
		output.append("Ciphertext C: ").append(result.getCiphertext()).append(System.lineSeparator());
		output.append("Key K: ").append(result.getKey()).append(System.lineSeparator());
		output.append("Plaintext P: ").append(result.getPlaintext()).append(System.lineSeparator());
	}


	/**
	 * Read in a text file with expected format Plaintext/Ciphertext on the first line and Key on the second line.
	 *
	 * @return Key, plaintext, ciphertext triplet
	 */
	private CryptoTriplet<String, String, String> readFile() {
		BufferedReader reader = null;
		try {
			String text = "";
			String key = "";

			reader = new BufferedReader(new FileReader(file));
			String line;
			int counter = 0;

			// Read through file line by line until no more lines
			while ((line = reader.readLine()) != null) {
				if (line.isEmpty()) continue;
				switch (counter++) {
					case 0:
						text = line;
						break;
					case 1:
						key = line;
						break;
					default:
						break;
				}
			}

			if (isEncryption)
				return new CryptoTriplet(key, text, "");
			return new CryptoTriplet(key, "", text);

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * Write a string into a a file based on the name of the given file.
	 * 
	 * @param file file selected by the user
	 * @param out string to be written
	 */
	private void writeFile() {
		BufferedWriter writer = null;

		try {
			String outputFileName = file.getPath().substring(0, file.getPath().lastIndexOf(".")) + "_output.txt";
			writer = new BufferedWriter(new FileWriter(outputFileName));
			writer.write(output.toString());
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				writer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
