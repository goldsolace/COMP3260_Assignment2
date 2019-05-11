import javax.swing.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Class Description
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 11-05-2019
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
        CryptoTriplet cyptoTriplet = readFile();
        if (cyptoTriplet == null) return;
        AES aes = new AES();
        if (isEncryption)
        {
            List<List<CryptoTriplet>> results = new ArrayList<>();

            long startTime = System.currentTimeMillis();

            // Explore each version of AES (AES0-AES4) on the orginal cryptoTriplet
            for (int aesVersion = 0; aesVersion < 5; aesVersion++)
            {
                aes.encrypt(cyptoTriplet, aesVersion);
            }

            for (int i = 0; i < KEY_SIZE; i++)
            {
                // Explore the changing of the ith bit
                byte[] ithKey = Utility.flipBit(cyptoTriplet.getKey(), i);
                byte[] ithPlaintext = Utility.flipBit(cyptoTriplet.getPlaintext(), i);
                //System.out.println(Utility.byteArrToBinaryString(ithKey));
                //System.out.println(Utility.byteArrToBinaryString(ithPlaintext));

                List<CryptoTriplet> cyptoTriplets = new ArrayList<>();
                // a) P and Pi under K
                cyptoTriplets.add(new CryptoTriplet(cyptoTriplet.getKey(), ithPlaintext, new byte[ithPlaintext.length]));
                // b) P under K and Ki
                cyptoTriplets.add(new CryptoTriplet(ithKey, cyptoTriplet.getPlaintext(), new byte[cyptoTriplet.getPlaintext().length]));

                // Explore each version of AES (AES0-AES4) on each of the current cryptoTriplets
                for (CryptoTriplet triplet : cyptoTriplets)
                {
                    for (int aesVersion = 0; aesVersion < 5; aesVersion++)
                    {
                        aes.encrypt(triplet, aesVersion);
                    }
                }

                // Store the results
                results.add(cyptoTriplets);
            }
            long runningTime = System.currentTimeMillis() - startTime;

            // Perform Avalanche effect analysis
            int[][][] analysis = AvalancheAnalysis(cyptoTriplet, results);
            GenerateEncryptionOutput(cyptoTriplet, analysis, runningTime);
        } else
        {
            aes.decrypt(cyptoTriplet, 0);
            GenerateDecryptionOutput(cyptoTriplet);
        }

        System.out.println(output.toString());
        writeFile();
    }

    /**
     * Performs avalanche effect analysis on the results and computes the average
     */
    private int[][][] AvalancheAnalysis(CryptoTriplet original, List<List<CryptoTriplet>> results)
    {
        // TODO Analysis
        int[][] pAndPiUnderKAverages = new int[Application.NUM_ROUNDS + 1][Application.NUM_VERSIONS];
        int[][] pUnderKAndKiAverages = new int[Application.NUM_ROUNDS + 1][Application.NUM_VERSIONS];

        for (List<CryptoTriplet> list : results)
        {
            CryptoTriplet PiUnderK = list.get(0);
            CryptoTriplet PUnderKi = list.get(1);
            for (int i = 0; i < NUM_VERSIONS; i++)
            {
                pAndPiUnderKAverages[0][i] = Utility.bitDifference(original.getPlaintext(), PiUnderK.getPlaintext());
                pUnderKAndKiAverages[0][i] = Utility.bitDifference(original.getPlaintext(), PUnderKi.getPlaintext());
            }
            for (int i = 0; i < NUM_ROUNDS; i++)
            {
                for (int j = 0; j < NUM_VERSIONS; j++)
                {
                    pAndPiUnderKAverages[i + 1][j] += Utility.bitDifference(original.getPlaintext(), PiUnderK.getIntermediateResults()[j][i]);
                    pUnderKAndKiAverages[i + 1][j] += Utility.bitDifference(original.getPlaintext(), PUnderKi.getIntermediateResults()[j][i]);
                }
            }
        }

        for (int i = 1; i < NUM_ROUNDS + 1; i++)
        {
            for (int j = 0; j < NUM_VERSIONS; j++)
            {
                pAndPiUnderKAverages[i][j] = Math.round((float) pAndPiUnderKAverages[i][j] / (KEY_SIZE-1));
                pUnderKAndKiAverages[i][j] = Math.round((float) pUnderKAndKiAverages[i][j] / (KEY_SIZE-1));
            }
        }

        int[][][] analysis = new int[2][][];
        analysis[0] = pAndPiUnderKAverages;
        analysis[1] = pUnderKAndKiAverages;
        return analysis;
    }

    private void printCryptoTriplet(CryptoTriplet c)
    {
        StringBuilder output = new StringBuilder();
        output.append("P: ")
                .append(Utility.byteArrToBinaryString(c.getPlaintext()))
                .append(System.lineSeparator());
        output.append("K: ")
                .append(Utility.byteArrToBinaryString(c.getKey()))
                .append(System.lineSeparator());
        output.append("C: ")
                .append(Utility.byteArrToBinaryString(c.getCiphertext()))
                .append(System.lineSeparator());
        System.out.println(output.toString());
    }

    /**
     * Appends the formatted result of decryption to output
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
        // TODO Rounds/Versions for analysis[0]
        GenerateAnalysisOutput(analysis[0]);
        output.append(System.lineSeparator());
        output.append("P under K and Ki")
                .append(System.lineSeparator());
        // TODO Rounds/Versions for analysis[1]
        GenerateAnalysisOutput(analysis[1]);
    }

    private void GenerateAnalysisOutput(int[][] analysis)
    {
        output.append(String.format("%-16s %-7s %-7s %-7s %-7s %-7s\n", "Round", "AES0", "AES1", "AES2", "AES3", "AES4"));
        for (int i = 0; i <= NUM_ROUNDS; i++)
        {
            output.append(String.format("%-16s  %-7s %-7s %-7s %-7s %-7s\n", i, analysis[i][0], analysis[i][1], analysis[i][2], analysis[i][3], analysis[i][4]));
        }
    }

    /**
     * Appends the formatted result of decryption to output
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
     * Write a string into a a file based on the name of the given file.
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