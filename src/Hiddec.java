import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;


public class Hiddec {

    public static void main(String[] args) {
        if(args.length != 3){
            System.out.println("Usage:\nHiddec: <inputFile> <outputFile> <keyFile>");
            return;
        }



        try{
            Hiddec hiddec = new Hiddec();

            hiddec.decrypt(args[0], args[1], args[2]);

        } catch(FileNotFoundException e) {

            System.out.println("one of the files were not found");
        } catch(IOException e){

            System.out.println("Something went wrong with IO. Do you own all of the files?");
        } catch(IncorrectKeyException e){

            System.out.println("The seems to not work");
        }
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

        byte[] key = hexFileToArray(keyFile);
        byte[] input = decrypt(getFileContents(inputFile), key);
        byte[] hashedKey = hash(getFileContents(keyFile));

        System.out.println(HexBin.encode(key));
        System.out.println(key.length + "\n");
        byte[] data = data(input, hashedKey);
        if (data == null)
            throw new IncorrectKeyException("Could not decrypt file");
        byte[] decrypted = decrypt(data, key);

        if (verify(decrypted, input)) {
            System.out.println(decrypted);
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

    private byte[] hexFileToArray(String file) throws IOException {

        String hexString = new String(getFileContents(file) , "UTF-8");
        return hexStringToByteArray(hexString);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len - 1; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }

        return data;
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
        int start = 0;
        int stop = 0;
        byte[] data = null;


        if ((start = findIndexOfData(input, hashedKey)) == -1)
            return null;

        start += hashedKey.length;

        data = Arrays.copyOfRange(input, start, input.length);

        if ((stop = findIndexOfData(input, hashedKey)) == -1)
            return null;

        input = Arrays.copyOfRange(input, stop, input.length);

        stop -= 1;

        return Arrays.copyOfRange(data, 0, stop);
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
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
            SecretKey secretKey = new SecretKeySpec(Arrays.copyOfRange(key, 0, key.length),"AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal();
        } catch (Exception e) {
            e.printStackTrace();
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

        return Collections.indexOfSubList(Arrays.asList(large), Arrays.asList(small));
    }

    private class IncorrectKeyException extends Exception {

        IncorrectKeyException(String s) {
            super(s);
        }
    }


}
