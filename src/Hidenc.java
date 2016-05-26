import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Random;

/**
 * Created by daseel on 2016-05-26.
 */
public class Hidenc {

    private String keyFile, offsetFile, inputFile, outputFile, templateFile, ctr;

    private int offset, size;

    public static void main(String[] args) {

        Hidenc hidenc = new Hidenc();
        hidenc.checkArgs(args);

        try {
            if (args.length == 4)
                hidenc.encryptToFile(args[0], args[1], args[2]);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Tfw stuff dont work");
        }
    }


    private void checkArgs(String[] args) throws IllegalArgumentException {

        if ((keyFile = getArg(args, "--key=")) == null)
            throw new IllegalArgumentException("no key was given");
        if ((inputFile = getArg(args, "--input=")) == null)
            throw new IllegalArgumentException("no input file was given");

        if ((outputFile = getArg(args, "--output=")) == null)
            throw new IllegalArgumentException("no output file was given");

        String size = null;
        if ((templateFile = getArg(args, "--template=")) != null && (size = getArg(args, "--size=")) != null)
            throw new IllegalArgumentException("template and size cannot be " +
                    "specified at the same time.");

        if(templateFile == null && size == null)
            throw new IllegalArgumentException("If template is not set, size needs to be set");

        if (size != null)
            this.size = Integer.parseInt(size);


        setOffset(args);

        ctr = getArg(args, "--ctr=");
    }

    private void setOffset(String[] args) {

        String offsetString = getArg(args, "--offset=");
        if (offsetString != null) {

            offset = Integer.parseInt(offsetString);
        } else {

            Random rand = new Random();
            offset = rand.nextInt();
        }
    }

    private String getArg(String[] args, String string) {

        for (String s : args) {
            if (s.startsWith(string))
                return s.replaceAll(string, "");

        }

        return null;
    }

    private void encryptToFile() throws IOException {
        byte[] data = getFileContents(inputFile);
        byte[] key = hexFileToArray(keyFile);
        byte[] CTR = hexStringToByteArray(ctr);
        int offset = 288;

        byte[] encrypted = encrypt(buildResult(data, key, offset), key, CTR);
        printToFile(encrypted, outputFile);
    }

    private byte[] buildResult(byte[] data, byte[] key, int offset) {

        byte[] result = new byte[1024];
        byte[] keyHash = hash(key);
        byte[] dataHash = hash(data);

        copyTo(result, keyHash, offset);
        copyTo(result, data, offset + keyHash.length);
        copyTo(result, keyHash, offset + keyHash.length + data.length);
        copyTo(result, dataHash, offset + keyHash.length * 2 + data.length);
        pad(result, 0, offset);
        pad(result, offset + keyHash.length * 2 + data.length + dataHash.length, result.length);

        return result;
    }

    private void copyTo(byte[] large, byte[] small, int start) {

        for (int i = start, j = 0; i < start + small.length; i++, j++)
            large[i] = small[j];
    }

    private void pad(byte[] data, int start, int stop) {

        Random random = new Random();

        for (int i = start; i < stop; i++) {
            byte rnd = (byte) random.nextInt();
            data[i] = rnd;
        }
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
    private byte[] encrypt(byte[] inputBytes, byte[] key, byte[] CTR) {

        byte[] encrypted = null;
        try {

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            encrypted = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Decryption is broken");
            System.exit(0);
        }

        return encrypted;
    }
}