import javax.swing.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Class Description
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 17-04-2019
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
            }
            else
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
            if (file != null) {
                Application app = new Application(isEncryption, file);
                app.run();
            } else {
                System.out.println("Error! Valid file not specified at command line or using file chooser GUI.");
            }
        }
        catch (Exception e)
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
                //aes.encrypt(cyptoTriplet, aesVersion);
            }

            for (int i = 0; i < KEY_SIZE; i++)
            {
                // Explore the changing of the ith bit
                byte[] ithKey = flipBit(cyptoTriplet.getKey(), i);
                byte[] ithPlaintext = flipBit(cyptoTriplet.getPlaintext(), i);
                //System.out.println(byteArrToBinaryString(ithKey));
                System.out.println(byteArrToBinaryString(ithPlaintext));
                if (true) continue;

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
                        aes.encrypt(cyptoTriplet, aesVersion);
                    }
                }

                // Store the results
                results.add(cyptoTriplets);
            }
            if (true) return;
            long runningTime = System.currentTimeMillis() - startTime;

            // Perform Avalanche effect analysis
            int[][][] analysis = AvalancheAnalysis(cyptoTriplet, results);
            GenerateEncryptionOutput(cyptoTriplet, analysis, runningTime);
        }
        else
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
    private void GenerateEncryptionOutput(CryptoTriplet original, int[][][] analysis, long runningTime)
    {
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
    private void GenerateDecryptionOutput(CryptoTriplet result)
    {
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

            byte[] text = binaryStrToByteArr(textStr);
            byte[] key = binaryStrToByteArr(keyStr);

            if (isEncryption)
                return new CryptoTriplet(key, text, new byte[text.length]);
            return new CryptoTriplet(key, new byte[text.length], text);

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                reader.close();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
        return null;
    }


    public byte[] binaryStrToByteArr(String str)
    {
        byte[] output = new byte[str.length() / Byte.SIZE];
        for (int i = 0; i < output.length; i++)
        {
            String part = str.substring(i * Byte.SIZE, (i + 1) * Byte.SIZE);
            output[i] = (byte) Integer.parseInt(part, 2);
        }
        return output;
    }

    public String byteArrToBinaryString(byte[] byteArr)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArr)
        {
            int byteInt = Byte.toUnsignedInt(b);
            int binary = Integer.parseInt(Integer.toBinaryString(byteInt));
            if (byteInt <= 127)
                sb.append(String.format("%08d", binary));
            else
                sb.append(String.format("%-8d", binary).replace(" ", "0"));
        }
        return sb.toString();
    }

    /**
     * Flips the ith bit in 128 bit byte array.
     *
     * @param byteArr 16 bytes long
     * @param i 0 - 127
     * @return copy of original byte array with the ith bit flipped
     */
    private byte[] flipBit(byte[] byteArr, int i)
    {
        byte[] newByteArr = byteArr.clone();
        int b = Byte.toUnsignedInt(byteArr[i/Byte.SIZE]);
        newByteArr[i/Byte.SIZE] = (byte) Math.floorMod(b ^ (1 << (Byte.SIZE - 1 - i % Byte.SIZE)), 256);
        return newByteArr;
    }

    /**
     * Calculate the number of different bits between two byte arrays
     *
     * @param arr1 first byte array
     * @param arr2 second byte array
     * @return int > 0 number of different bits
     */
    public static int bitDifference(byte[] arr1, byte[] arr2)
    {
        int diff = 0;
        for (int i = 0; i < arr1.length; i++)
        {
            int byte1 = Byte.toUnsignedInt(arr1[i]);
            int byte2 = Byte.toUnsignedInt(arr2[i]);
            diff += Integer.bitCount(byte1 ^ byte2);
        }
        return diff;
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
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                writer.close();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
    }
}