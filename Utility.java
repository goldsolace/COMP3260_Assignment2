/**
 * Utility methods
 *
 * @author Brice Purton - c3180044
 * @author Jeremiah Smith - c3238179
 * @since 11-05-2019
 */

public class Utility
{
    /**
     * Convert 2D array to 1D array.
     *
     * @param arr 2D array
     * @return 1D array
     */
    public static int[] convertArray(int[][] arr)
    {
        int m = arr.length;
        int n = arr[0].length;
        int[] newArr = new int[m * n + n];
        for (int i = 0; i < arr.length; i++)
        {
            for (int j = 0; j < arr[0].length; j++)
            {
                int position = i * n + j;
                newArr[position] = arr[i][j];
            }
        }
        return newArr;
    }

    /**
     * Convert a binary string to a byte array.
     *
     * @param binaryStr string containing 1s and 0s
     * @return byte array representation of binary string
     */
    public static byte[] binaryStrToByteArr(String binaryStr)
    {
        byte[] output = new byte[binaryStr.length() / Byte.SIZE];
        for (int i = 0; i < output.length; i++)
        {
            String part = binaryStr.substring(i * Byte.SIZE, (i + 1) * Byte.SIZE);
            output[i] = (byte) Integer.parseInt(part, 2);
        }
        return output;
    }

    /**
     * Convert a byte array to a binary string.
     *
     * @param byteArr
     * @return binary representation of byte array
     */
    public static String byteArrToBinaryString(byte[] byteArr)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArr)
        {
            int byteInt = Byte.toUnsignedInt(b);
            int binary = Integer.parseInt(Integer.toBinaryString(byteInt));
            // Pad leading zeros
            if (byteInt <= 127)
                sb.append(String.format("%08d", binary));
                // Pad trailing zeros
            else
                sb.append(binary);
            //sb.append(String.format("%-8d", binary).replace(" ", "0"));
        }
        return sb.toString();
    }

    /**
     * Convert an int array to a byte array.
     *
     * @param intArr
     * @return byte array
     */
    public static byte[] intArrToByteArr(int[] intArr)
    {
        byte[] byteArr = new byte[intArr.length];
        for (int i = 0; i < intArr.length; i++)
        {
            byteArr[i] = (byte) intArr[i];
        }
        return byteArr;
    }

    /**
     * Convert a byte array to an int array.
     *
     * @param byteArr
     * @return int array
     */
    public static int[] byteArrToIntArr(byte[] byteArr)
    {
        int[] intArr = new int[byteArr.length];
        for (int i = 0; i < byteArr.length; i++)
            intArr[i] = Byte.toUnsignedInt(byteArr[i]);
        return intArr;
    }

    /**
     * Flips the ith bit in 128 bit byte array.
     *
     * @param byteArr 16 bytes long
     * @param i       0 - 127
     * @return copy of original byte array with the ith bit flipped
     */
    public static byte[] flipBit(byte[] byteArr, int i)
    {
        byte[] newByteArr = byteArr.clone();
        int b = Byte.toUnsignedInt(byteArr[i / Byte.SIZE]);
        newByteArr[i / Byte.SIZE] = (byte) Math.floorMod(b ^ (1 << (Byte.SIZE - 1 - i % Byte.SIZE)), 256);
        return newByteArr;
    }

    /**
     * Calculate the number of different bits between two byte arrays
     *
     * @param arr1 first byte array
     * @param arr2 second byte array
     * @return number of different bits
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
}
