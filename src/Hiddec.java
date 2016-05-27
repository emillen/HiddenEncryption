import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

public class Hiddec {

    private String key, ctr, inputFile, outputFile;
    private IvParameterSpec CTR = null;
    private Cipher cipher;

    public static void main(String[] args) {

        try {
            Hiddec hiddec = new Hiddec();
            hiddec.getArgs(args);
            hiddec.decryptFile();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Something went wrong with IO. Do you own all of the files, or does the files not exist?");
        } catch (IncorrectKeyException e) {
            e.printStackTrace();
            System.out.println("Passsword seems to not work");
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }
    }


    private void getArgs(String[] args) throws IllegalArgumentException {
        if ((key = getArg(args, "--key=")) == null)
            throw new IllegalArgumentException("Key is not set");

        ctr = getArg(args, "--ctr=");


        if ((inputFile = getArg(args, "--input=")) == null)
            throw new IllegalArgumentException("input file is not set");

        if ((outputFile = getArg(args, "--output=")) == null)
            throw new IllegalArgumentException("output file is not set");
    }

    private String getArg(String[] args, String string) {

        for (String s : args) {
            if (s.startsWith(string))
                return s.replaceAll(string, "");

        }

        return null;
    }

    /**
     * Decrypts, and prints, the data file
     *
     * @throws IOException           when something went wrong with reading the files
     * @throws IncorrectKeyException when the file could not be decrypted (probs wrong key haha)
     */
    private void decryptFile() throws IOException, IncorrectKeyException {

        byte[] key = hexStringToByteArray(this.key);
        if (ctr != null)
            CTR = new IvParameterSpec(hexStringToByteArray(ctr));
        byte[] input = getFileContents(inputFile);

        Data data = new Data(input, key);

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
        if (file == null) return null;

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


    private class IncorrectKeyException extends Exception {

        IncorrectKeyException(String s) {
            super(s);
        }
    }

    private class Data {

        private byte[] data;
        private byte[] hashOfData;
        private SecretKey secretKey;

        Data(byte[] input, byte[] key) {

            secretKey = new SecretKeySpec(key, "AES");
            data = data(input, key);
        }

        private void initCipher() {

            try {
                if (CTR == null) {
                    cipher = Cipher.getInstance("AES/ECB/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                } else {
                    cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, CTR);
                }
            } catch (Exception e) {
                System.out.println("Algorithm was not found");
                System.exit(0);
            }
        }

        /**
         * Returns the data in between two sections containing the hashed key
         * A side effect is that the input array is shortened to the last part
         * that contains the H(data)
         *
         * @param input the input to search in
         * @param key   the key
         * @return null if data could not be found, else the data
         */
        private byte[] data(byte[] input, byte[] key) {
            int start;
            int stop;
            byte[] data;

            // find starting position
            if ((start = indexOf(input, key)) == -1)
                return null;

            start += key.length;

            data = Arrays.copyOfRange(input, start, input.length);


            // find data
            if ((data = getData(data, key)) == null)
                return null;

            stop = start + data.length;

            // the last part of the input
            hashOfData = Arrays.copyOfRange(input, stop + key.length, input.length);

            try {
                hashOfData = cipher.doFinal(Arrays.copyOfRange(hashOfData, 0, 16));
            } catch (Exception e) {
                System.out.println("Decryption broken");
                System.exit(0);
            }
            return data;
        }


        private byte[] getData(byte[] input, byte[] key) {
            byte[] hashedKey = hash(key);
            byte[] data = null;

            for (int i = 0; i <= input.length - 16; i += 16) {
                byte[] decryptedBlock = decrypt(input, i, i + 16);
                if (Arrays.equals(decryptedBlock, hashedKey))
                    return data;
                else
                    data = concat(data, decryptedBlock);
            }

            return null;
        }

        private byte[] concat(byte[] a, byte[] b) {

            if (a == null)
                return Arrays.copyOfRange(b, 0, b.length);
            if (b == null)
                return Arrays.copyOfRange(a, 0, a.length);

            byte[] newArray = new byte[a.length + b.length];

            System.arraycopy(a, 0, newArray, 0, a.length);
            System.arraycopy(b, 0, newArray, a.length, b.length);
            return newArray;
        }

        /**
         * Finds the index of the patter in decrypted data
         *
         * @param data the data to decrypt and look in
         * @param key  the pattern to look for
         * @return -1 if it fails, else the index
         */
        private int indexOf(byte[] data, byte[] key) {
            byte[] hashedKey = hash(key);

            for (int i = 0; i <= data.length - 16; i += 16) {

                initCipher();

                if (Arrays.equals(decrypt(data, i, i + 16), hashedKey))
                    return i;
            }

            return -1;
        }

        /**
         * Decrypts the input bytes
         *
         * @param inputBytes the bytes to be decrypted
         * @return decrypted bytes
         */
        private byte[] decrypt(byte[] inputBytes, int from, int to) {

            byte[] decrypted = null;
            try {
                byte[] copyOfRange = Arrays.copyOfRange(inputBytes, from, to);
                decrypted = cipher.update(copyOfRange);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Decryption is broken");
                System.exit(0);
            }
            return decrypted;
        }
    }
}
