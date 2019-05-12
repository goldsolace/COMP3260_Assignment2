import javax.swing.*;
import java.io.*;

/**
 * Application demonstrating 10 round AES encryption and decryption of a single plaintext block.
 * Take as input a 128 bit plaintext block and a 128 bit key and produce as output a 128 bit ciphertext
 * block, or a 128 bit ciphertext block and a 128 bit key and produce as output a 128 bit plaintext block.
 *
 * Encryption explores the Avalanche effect of the original Advanced Encryption Standard denoted
 * as AES0, as well as AES1, AES2, AES3 and AES4, where in each version an operation is missing in each round
 * as follows:
 *      0. AES0 - the original version of AES
 *      1. AES1 – SubstituteBytes is missing from all rounds
 *      2. AES2 – ShiftRows is missing from all rounds
 *      3. AES3 – MixColumns is missing from all rounds
 *      4. AES4 - AddRoundKey is missing from all rounds
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 12-05-2019
 */

public class Application
{
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
     * @param file         file to run application with
     */
    public Application(boolean isEncryption, File file)
    {
        this.isEncryption = isEncryption;
        this.file = file;
        output = new StringBuilder();
    }

    /**
     * Main Method.
     *
     * @param args command line arguments
     */
    public static void main(String[] args)
    {
        File file = null;
        boolean isEncryption;

        // Get operation and file from command line args or gui file chooser
        try
        {
            if (args.length > 0)
            {
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
            } else
            {
                Object[] options = {"Encryption", "Decryption"};
                isEncryption = JOptionPane.showOptionDialog(null, "Operation?", "Please choose an opteration",
                        JOptionPane.YES_NO_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, null) == JOptionPane.YES_OPTION;
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
                if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION)
                    file = fileChooser.getSelectedFile();
            }

            // Run the simulation on selected file
            if (file != null)
            {
                Application app = new Application(isEncryption, file);
                app.run();
            } else
            {
                System.out.println("Error! Valid file not specified at command line or using file chooser GUI.");
            }
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Run the application.
     */
    public void run()
    {
        CryptoTriplet cryptoTriplet = readFile();
        if (cryptoTriplet == null) return;
        AES aes = new AES();
        if (isEncryption)
        {
            CryptoTriplet[][] cryptoTriplets = new CryptoTriplet[KEY_SIZE][2];

            long startTime = System.currentTimeMillis();
            long runningTime = 0L;

            // Explore each version of AES (AES0-AES4) on the orginal cryptoTriplet
            for (int aesVersion = 0; aesVersion < 5; aesVersion++)
            {
                aes.encrypt(cryptoTriplet, aesVersion);
                // Running time = time to encrypt original plaintext under AES0
                if (aesVersion == 0)
                    runningTime = System.currentTimeMillis() - startTime;
            }

            // Explore the changing of the ith bit from 0 to 128
            for (int i = 0; i < KEY_SIZE; i++)
            {
                byte[] ithKey = Utility.flipBit(cryptoTriplet.getKey(), i);
                byte[] ithPlaintext = Utility.flipBit(cryptoTriplet.getPlaintext(), i);

                // a) P and Pi under K
                cryptoTriplets[i][0] = new CryptoTriplet(cryptoTriplet.getKey(), ithPlaintext, null);
                // b) P under K and Ki
                cryptoTriplets[i][1] = new CryptoTriplet(ithKey, cryptoTriplet.getPlaintext(), null);

                // Explore each version of AES (AES0-AES4) on current cryptoTriplet pair
                for (CryptoTriplet triplet : cryptoTriplets[i])
                {
                    for (int aesVersion = 0; aesVersion < NUM_VERSIONS; aesVersion++)
                    {
                        aes.encrypt(triplet, aesVersion);
                    }
                }
            }

            // Perform Avalanche effect analysis
            int[][][] analysis = AvalancheAnalysis(cryptoTriplet, cryptoTriplets);
            GenerateEncryptionOutput(cryptoTriplet, analysis, runningTime);

        } else
        {
            aes.decrypt(cryptoTriplet);
            GenerateDecryptionOutput(cryptoTriplet);
        }

        System.out.println(output.toString());
        writeFile();
    }

    /**
     * Performs avalanche effect analysis on the results of encryption.
     *
     * @param original Cryptotriplet containing original plaintext, key and ciphertext
     * @param results Array of 128 pairs containing PiUnderK and PUnderKi with the ith bit flipped in plaintext or key
     * @return 3D Matrix[2][Round][version] containing averages
     */
    private int[][][] AvalancheAnalysis(CryptoTriplet original, CryptoTriplet[][] results)
    {
        int[][] pAndPiUnderKAverages = new int[Application.NUM_ROUNDS + 1][Application.NUM_VERSIONS];
        int[][] pUnderKAndKiAverages = new int[Application.NUM_ROUNDS + 1][Application.NUM_VERSIONS];

        for (CryptoTriplet[] pair : results)
        {
            CryptoTriplet PiUnderK = pair[0];
            CryptoTriplet PUnderKi = pair[1];
            // Round 0 (Before any Encryption)
            for (int version = 0; version < NUM_VERSIONS; version++)
            {
                pAndPiUnderKAverages[0][version] = Utility.bitDifference(original.getPlaintext(), PiUnderK.getPlaintext());
                pUnderKAndKiAverages[0][version] = Utility.bitDifference(original.getPlaintext(), PUnderKi.getPlaintext());
            }
            // Sum bitDifference of [round][version] intermediate state
            for (int round = 0; round < NUM_ROUNDS; round++)
            {
                for (int version = 0; version < NUM_VERSIONS; version++)
                {
                    pAndPiUnderKAverages[round + 1][version] += Utility.bitDifference(original.getIntermediateState(version, round), PiUnderK.getIntermediateState(version, round));
                    pUnderKAndKiAverages[round + 1][version] += Utility.bitDifference(original.getIntermediateState(version, round), PUnderKi.getIntermediateState(version, round));
                }
            }
        }

        // Calculate Average = Total bit difference of [round][version] / 128
        for (int round = 1; round < NUM_ROUNDS + 1; round++)
        {
            for (int version = 0; version < NUM_VERSIONS; version++)
            {
                pAndPiUnderKAverages[round][version] = Math.round((float)pAndPiUnderKAverages[round][version] / KEY_SIZE);
                pUnderKAndKiAverages[round][version] = Math.round((float)pUnderKAndKiAverages[round][version] / KEY_SIZE);
            }
        }

        int[][][] analysis = new int[2][][];
        analysis[0] = pAndPiUnderKAverages;
        analysis[1] = pUnderKAndKiAverages;
        return analysis;
    }

    /**
     * Appends the formatted result of encryption to output including avalanche analysis.
     *
     * @param original Cryptotriplet containing original plaintext, key and ciphertext
     * @param analysis 3D Matrix[2][Round][version] containing avalanche analysis
     * @param runningTime time to complete encryption of all plaintext/key pairs
     */
    private void GenerateEncryptionOutput(CryptoTriplet original, int[][][] analysis, long runningTime)
    {
        output.append("ENCRYPTION")
                .append(System.lineSeparator());
        output.append("Plaintext P: ")
                .append(Utility.byteArrToBinaryString(original.getPlaintext()))
                .append(System.lineSeparator());
        output.append("Key K: ")
                .append(Utility.byteArrToBinaryString(original.getKey()))
                .append(System.lineSeparator());
        output.append("Ciphertext C: ")
                .append(Utility.byteArrToBinaryString(original.getCiphertext()))
                .append(System.lineSeparator());
        output.append("Running time: ")
                .append(runningTime)
                .append("ms")
                .append(System.lineSeparator());
        output.append("Avalanche: ")
                .append(System.lineSeparator());
        output.append("P and Pi under K")
                .append(System.lineSeparator());
        GenerateAnalysisOutput(analysis[0]);
        output.append(System.lineSeparator());
        output.append("P under K and Ki")
                .append(System.lineSeparator());
        GenerateAnalysisOutput(analysis[1]);
    }

    /**
     * Format analysis by rounds and version and add to output.
     *
     * @param analysis 2D Matrix[Round][Version]
     */
    private void GenerateAnalysisOutput(int[][] analysis)
    {
        output.append(String.format("%-16s %-7s %-7s %-7s %-7s %-7s\n", "Round", "AES0", "AES1", "AES2", "AES3", "AES4"));
        for (int round = 0; round <= NUM_ROUNDS; round++)
        {
            output.append(String.format("   %-15s", round));
            for (int avgDiff : analysis[round]) {
                output.append(String.format(" %-7s", avgDiff));
            }
            output.append(System.lineSeparator());
        }
    }

    /**
     * Appends the formatted result of decryption to output.
     *
     * @param result Cryptotriplet containing plaintext, key and ciphertext
     */
    private void GenerateDecryptionOutput(CryptoTriplet result)
    {
        output.append("DECRYPTION")
                .append(System.lineSeparator());
        output.append("Ciphertext C: ")
                .append(Utility.byteArrToBinaryString(result.getCiphertext()))
                .append(System.lineSeparator());
        output.append("Key K: ")
                .append(Utility.byteArrToBinaryString(result.getKey()))
                .append(System.lineSeparator());
        output.append("Plaintext P: ")
                .append(Utility.byteArrToBinaryString(result.getPlaintext()))
                .append(System.lineSeparator());
    }


    /**
     * Read in a text file with expected format Plaintext/Ciphertext on the first line and Key on the second line.
     *
     * @return Key, plaintext, ciphertext triplet
     */
    private CryptoTriplet readFile()
    {
        BufferedReader reader = null;
        try
        {
            String textStr = "";
            String keyStr = "";

            reader = new BufferedReader(new FileReader(file));
            String line;
            int counter = 0;

            // Read through file line by line until no more lines
            while ((line = reader.readLine()) != null)
            {
                if (line.isEmpty()) continue;
                line = line.trim();
                if (line.length() > 128 || line.matches("[^01]")) throw new Exception("File must contain 128 bit binary strings only");
                switch (counter++)
                {
                    case 0:
                        textStr = line;
                        break;
                    case 1:
                        keyStr = line;
                        break;
                    default:
                        break;
                }
            }

            byte[] text = Utility.binaryStrToByteArr(textStr);
            byte[] key = Utility.binaryStrToByteArr(keyStr);

            if (isEncryption)
                return new CryptoTriplet(key, text, new byte[text.length]);
            return new CryptoTriplet(key, new byte[text.length], text);

        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            try
            {
                reader.close();
            } catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * Write a output into a a file based on the name of the given file.
     */
    private void writeFile()
    {
        BufferedWriter writer = null;
        try
        {
            String outputFileName = file.getPath().substring(0, file.getPath().lastIndexOf(".")) + "_output.txt";
            writer = new BufferedWriter(new FileWriter(outputFileName));
            writer.write(output.toString());
        } catch (IOException e)
        {
            e.printStackTrace();
        } finally
        {
            try
            {
                writer.close();
            } catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }
}