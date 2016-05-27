import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
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

    private String keyFile, inputFile, outputFile, templateFile, ctr;

    private int offset, size;

    public static void main(String[] args) {


        try {
            Hidenc hidenc = new Hidenc();
            hidenc.checkArgs(args);
            hidenc.encryptToFile();
        } catch (Exception e) {
            e.printStackTrace();

            System.out.println("Something went wrong:\n");
            System.out.println(e.getMessage());
        }
    }


    private void checkArgs(String[] args) throws IllegalArgumentException {

        if ((keyFile = getArg(args, "--key=")) == null)
            throw new IllegalArgumentException("no key was given");
        if ((inputFile = getArg(args, "--input=")) == null)
            throw new IllegalArgumentException("no input file was given");

        if ((outputFile = getArg(args, "--output=")) == null)
            throw new IllegalArgumentException("no output file was given");

        String size;
        if ((size = getArg(args, "--size=")) != null && (templateFile = getArg(args, "--template=")) != null)
            throw new IllegalArgumentException("template and size cannot be " +
                    "specified at the same time.");

        if (size == null && templateFile == null)
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

            offset = -1;
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
        byte[] key = hexStringToByteArray(keyFile);
        byte[] CTR = hexStringToByteArray(ctr);

        byte[] encrypted = buildResult(data, key, CTR);
        printToFile(encrypted, outputFile);
    }

    private byte[] buildResult(byte[] data, byte[] key, byte[] CTR) throws IOException {

        byte[] result;

        if (templateFile != null)
            result = getFileContents(templateFile);
        else
            result = new byte[size];

        if (offset == -1)
            while ((offset = new Random().nextInt(result.length) % 16) != 0) ;


        byte[] keyHash = hash(key);
        byte[] dataHash = hash(data);
        byte[] blob = new byte[data.length + keyHash.length * 2 + dataHash.length];

        copyTo(blob, keyHash, 0);
        copyTo(blob, data, keyHash.length);
        copyTo(blob, keyHash, keyHash.length + data.length);
        copyTo(blob, dataHash, keyHash.length * 2 + data.length);

        copyTo(result, encrypt(blob, key, CTR), offset);

        if (templateFile == null) {
            System.out.println("ingen tempfile");
            pad(result, 0, offset);
            pad(result, offset + keyHash.length * 2 + data.length + dataHash.length, result.length);
        }
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
        if (s == null)
            return null;

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
            Cipher cipher;
            if (CTR == null) {
                cipher = Cipher.getInstance("AES/ECB/NoPadding");
                SecretKey secretKey = new SecretKeySpec(key, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            } else {
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                SecretKey secretKey = new SecretKeySpec(key, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(CTR);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            }

            encrypted = cipher.doFinal(inputBytes);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Decryption is broken");
            System.exit(0);
        }

        return encrypted;
    }
}
