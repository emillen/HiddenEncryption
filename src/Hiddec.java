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

        int length = input.length;

        Data data = new Data(input, hashedKey);

        if (data.data == null)
            throw new IncorrectKeyException("Could not decryptFile file");
        byte[] decrypted = decrypt(data.data, key);
        if (verify(decrypted, data.hashOfData)) {

            System.out.println(length == input.length);
            System.out.println(new String(decrypted, "UTF-8"));
            printToFile(decrypted, outputFile);
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

        return Arrays.equals(hash(decrypted), hOfData);
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
            System.out.println("Error: Program shouldnt break here, but for some reason the hash algorithm does not excist");
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
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            System.out.println((float) inputBytes.length / 16);
            decrypted = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Stuff went wrong, bye friend, have a good life");
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

        byte[] getData() {
            return data;
        }

        byte[] getHashOfData() {

            return hashOfData;
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

            if ((start = findIndexOfData(input, hashedKey)) == -1)
                return null;

            data = Arrays.copyOfRange(input, start + hashedKey.length, input.length);

            if ((stop = findIndexOfData(input, hashedKey)) == -1)
                return null;


            hashOfData = Arrays.copyOfRange(input, stop + hashedKey.length, input.length);

            try {
                System.out.println(new String(Arrays.copyOfRange(input, stop, stop + hashedKey.length), "UTF-8"));
                System.out.println(new String(hashedKey, "UTF-8"));
            } catch (Exception e){
                System.out.println("Hora");
            }
            return Arrays.copyOfRange(data, 0, stop - 1);
        }

        /**
         * Finds the index of the data inside the blob
         *
         * @param large the large array to search in
         * @param small the small array to find inside the large array
         * @return -1 if not found, or the index if it found
         */
        private int findIndexOfData(byte[] large, byte[] small) {
            String bigStr = new String(large);
            String smallStr = new String(small);

            return bigStr.indexOf(smallStr);
        }
    }
}
