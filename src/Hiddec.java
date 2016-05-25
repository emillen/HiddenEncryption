import java.io.FileNotFoundException;
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

        byte[] input = decrypt(getFileContents(inputFile));
        byte[] hashedKey = hash(getFileContents(keyFile));


    }

    private byte[] getFileContents(String file) throws FileNotFoundException, IOException {

        return Files.readAllBytes(Paths.get(file));

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
            return null;
        }
    }

    /**
     * Decrypts the input bytes
     *
     * @param inputBytes the bytes to be decrypted
     * @return decrypted bytes
     */
    private byte[] decrypt(byte[] inputBytes) {

        return null;
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

        public IncorrectKeyException(String s) {
            super(s);
        }
    }
}
