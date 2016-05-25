import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;


public class Hiddec {

    public static void main(String[] args) {

    }


    /**
     * Decrypts the data file and returns its values
     *
     * @param inputFile  the input file
     * @param outputFile the output file to save the decrypted data in
     * @param keyFile    the file containing the key
     * @throws FileNotFoundException when one of the files does not exist
     * @throws IOException           when something went wrong with reading the files
     * @throws IncorrectKeyException when the file could not be decrypted (probs wrong key haha)
     */
    public void decrypt(String inputFile, String outputFile, String keyFile) throws FileNotFoundException, IOException, IncorrectKeyException {

        byte[] key = getFileContents(keyFile);
        byte[] input = decrypt(getFileContents(inputFile), key);
        byte[] hashedKey = hash(getFileContents(keyFile));

        byte[] data = data(input, hashedKey);
        if (data == null)
            throw new IncorrectKeyException("Could not decrypt file");
        printToFile(data, outputFile);

    }

    /**
     * Returns all the bytes from a file
     *
     * @param file the name of the file to be read
     * @return a byte array with all the bytes in the file
     * @throws FileNotFoundException when the file is not found
     * @throws IOException           when something went wrong with the input
     */
    private byte[] getFileContents(String file) throws FileNotFoundException, IOException {

        return Files.readAllBytes(Paths.get(file));

    }

    /**
     * prints a bytearray to a file
     *
     * @param data       the byte array to print
     * @param outPutFile the file to print to
     * @throws FileNotFoundException when the file is not found
     * @throws IOException           when something went wrong with the output
     */
    private void printToFile(byte[] data, String outPutFile) throws FileNotFoundException, IOException {

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
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(inputBytes);
            return md.digest();

        } catch (Exception e) {
            System.out.println("Error: Program shouldnt break here, but for some reason the hash algorithm does not excist");
            System.exit(0);
        }
        return null;  // Dont think it should get here really
    }

    private byte[] data(byte[] input, byte[] hashedKey) {


        return null;
    }

    /**
     * Decrypts the input bytes
     *
     * @param inputBytes the bytes to be decrypted
     * @param key        the bytes in the key
     * @return decrypted bytes
     */
    private byte[] decrypt(byte[] inputBytes, byte[] key) {

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal();
        } catch (Exception e) {

            System.out.println("Stuff went wrong, bye friend, have a good life");
            System.exit(0);
        }

        return null;  // Probably will never get here
    }


    /**
     * Finds the index of the data inside the blob
     *
     * @param large the large array to search in
     * @param small the small array to find inside the large array
     * @return -1 if not found, or the index if it found
     */
    private int findIndexOfData(byte[] large, byte[] small) {

        return -1;
    }

    private class IncorrectKeyException extends Exception {

        IncorrectKeyException(String s) {
            super(s);
        }
    }
}
