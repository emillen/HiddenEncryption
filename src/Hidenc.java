import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

/**
 * Created by daseel on 2016-05-26.
 */
public class Hidenc {

    public static void main(String[] args) {

        if (args.length != 4) {
            System.out.println("Usage: Hidenc <datafile> <keyfile> <offsetfile> <savefile>");
            return;
        }
        try{
            Hidenc hidenc = new Hidenc();
            hidenc.encryptToFile(args[0], args[1], args[2]);
        } catch(Exception e) {

            System.out.println("Tfw stuff dont work");
        }
    }


    private void encryptToFile(String datafile, String keyfile, String saveFile) throws IOException {
        byte[] data = getFileContents(datafile);
        byte[] key = hexFileToArray(keyfile);
        byte[] blob = encrypt(data, key);
        int offset = 288;

        printToFile(buildResult(blob, key, offset), saveFile);
    }

    private byte[] buildResult(byte[] blob, byte[] key, int offset) {

        byte[] result = new byte[1024];


    }

    private void pad(){


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
     * Encrypts the input bytes
     *
     * @param inputBytes the bytes to be decrypted
     * @param key        the bytes in the key
     * @return decrypted bytes
     */
    private byte[] encrypt(byte[] inputBytes, byte[] key) {

        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            decrypted = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Decryption is broken");
            System.exit(0);
        }

        return decrypted;
    }
}
