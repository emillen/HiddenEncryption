import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

public class Hiddec {

    public static void main(String[] args) {

        if (args.length != 3) {
            System.out.println("Usage:\nHiddec: <inputFile> <outputFile> <keyFile>");
            return;
        }

        try {
            Hiddec hiddec = new Hiddec();
            hiddec.decryptFile(args[0], args[1], args[2]);

        } catch (IOException e) {
            System.out.println("Something went wrong with IO. Do you own all of the files, or does the files not exist?");
        } catch (IncorrectKeyException e) {
            e.printStackTrace();
            System.out.println("The seems to not work");
        }
    }

    /**
     * Decrypts the data file and returns its values
     *
     * @param inputFile  the input file
     * @param outputFile the output file to save the decrypted data in
     * @param keyFile    the file containing the key
     * @throws IOException           when something went wrong with reading the files
     * @throws IncorrectKeyException when the file could not be decrypted (probs wrong key haha)
     */
    private void decryptFile(String inputFile, String outputFile, String keyFile) throws IOException, IncorrectKeyException {

        byte[] key = hexFileToArray(keyFile);
        byte[] input = decrypt(getFileContents(inputFile), key);
        byte[] hashedKey = hash(key);

        Data data = new Data(input, hashedKey);

        if (data.data == null)
            throw new IncorrectKeyException("Could not decrypt file");

        if (verify(data.data, data.hashOfData)) {
            System.out.println(new String(data.data, "UTF-8"));
            printToFile(data.data, outputFile);
        } else {

            System.out.println("Could not verify the file");
        }
    }

    /**
     * Checks if the hash of decrypted is the same as hOfData
     *
     * @param decrypted the array to hash
     * @param hOfData   the value to verify
     * @return true if same, else false
     */
    private boolean verify(byte[] decrypted, byte[] hOfData) {

        byte[] hash = hash(decrypted);
        return Arrays.equals(hash, hOfData);
    }


    /**
     * Reads a file with hex-numbers and returns a byte array representing that file
     *
     * @param file the name of the file to read
     * @return a byte array of hex numbers
     * @throws IOException when the file could not be read
     */
    private byte[] hexFileToArray(String file) throws IOException {

        String hexString = new String(getFileContents(file), "UTF-8");
        return hexStringToByteArray(hexString);
    }


    /**
     * takes an hex-string, and returns an byte array representing that hex string
     *
     * @param s the hex-string
     * @return a byte-array
     */
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len - 1; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }

    /**
     * Returns all the bytes from a file
     *
     * @param file the name of the file to be read
     * @return a byte array with all the bytes in the file
     * @throws IOException when something went wrong with the input
     */
    private byte[] getFileContents(String file) throws IOException {

        return Files.readAllBytes(Paths.get(file));
    }

    /**
     * prints a bytearray to a file
     *
     * @param data       the byte array to print
     * @param outPutFile the file to print to
     * @throws IOException when something went wrong with the output
     */
    private void printToFile(byte[] data, String outPutFile) throws IOException {

        FileOutputStream out = new FileOutputStream(outPutFile);
        out.write(data);
        out.close();
    }

    /**
     * Hashses the input bytes using MD5
     *
     * @param inputBytes the bytes to hash
     * @return hashed bytes
     */
    private byte[] hash(byte[] inputBytes) {
        MessageDigest md;
        byte[] hash = null;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(inputBytes);
            hash = md.digest();

        } catch (Exception e) {
            System.out.println("Error: Program shouldnt break here, but " +
                    "for some reason the hash algorithm does not exist");
            System.exit(0);
        }
        return hash;
    }


    /**
     * Decrypts the input bytes
     *
     * @param inputBytes the bytes to be decrypted
     * @param key        the bytes in the key
     * @return decrypted bytes
     */
    private byte[] decrypt(byte[] inputBytes, byte[] key) {

        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            decrypted = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Decryption is broken");
            System.exit(0);
        }

        return decrypted;
    }


    private class IncorrectKeyException extends Exception {

        IncorrectKeyException(String s) {
            super(s);
        }
    }

    private class Data {

        private byte[] data;
        private byte[] hashOfData;


        Data(byte[] input, byte[] hashedKey) {

            data = data(input, hashedKey);
        }

        /**
         * Returns the data in between two sections containing the hashed key
         * A side effect is that the input array is shortened to the last part
         * that contains the H(data)
         *
         * @param input     the input to search in
         * @param hashedKey the hashed key
         * @return null if data could not be found, else the data
         */
        private byte[] data(byte[] input, byte[] hashedKey) {
            int start;
            int stop;
            byte[] data;

            // find starting position
            if ((start = indexOf(input, hashedKey)) == -1)
                return null;

            data = Arrays.copyOfRange(input, start + hashedKey.length, input.length);

            // find stop position
            if ((stop = indexOf(data, hashedKey)) == -1)
                return null;

            // the last part of the input
            hashOfData = Arrays.copyOfRange(data, stop + hashedKey.length, data.length);
            hashOfData = Arrays.copyOfRange(hashOfData, 0, 16);

            return Arrays.copyOfRange(data, 0, stop);
        }

        /**
         * Finds the index of the patter in data
         *
         * @param data    the data to look in
         * @param pattern the pattern to look for
         * @return -1 if it fails, else the index
         */
        private int indexOf(byte[] data, byte[] pattern) {
            int[] failure = computeFailure(pattern);

            int j = 0;
            if (data.length == 0) return -1;

            for (int i = 0; i < data.length; i++) {
                while (j > 0 && pattern[j] != data[i]) {
                    j = failure[j - 1];
                }
                if (pattern[j] == data[i]) {
                    j++;
                }
                if (j == pattern.length) {
                    return i - pattern.length + 1;
                }
            }
            return -1;
        }

        private int[] computeFailure(byte[] pattern) {
            int[] failure = new int[pattern.length];

            int j = 0;
            for (int i = 1; i < pattern.length; i++) {
                while (j > 0 && pattern[j] != pattern[i]) {
                    j = failure[j - 1];
                }
                if (pattern[j] == pattern[i]) {
                    j++;
                }
                failure[i] = j;
            }

            return failure;
        }

    }
}
