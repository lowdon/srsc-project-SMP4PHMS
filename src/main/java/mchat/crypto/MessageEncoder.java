package mchat.crypto;

import mchat.utils.Utils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

// this class will hold all crypto algorithms able to be called
public class MessageEncoder {

    //this will be the algorithm used for symmetric encryption. set it in the security.conf!!!
    private String confidentiality;
    private String cAlgorithm; //name of alg in confidentiality
    private byte[] keyBytes;

    public MessageEncoder(){
        InputStream secConf;
        secConf = getClass().getResourceAsStream("/security.conf");
        Properties props = new Properties();
        try {
            props.load(secConf);
        } catch (IOException e) {
            throw new RuntimeException("No such file");
        }
        confidentiality = props.getProperty("CONFIDENTIALITY");
        String confKeyS = props.getProperty("CONFIDENTIALITY-KEY");
        System.out.println("THIS IS THE CONFIDENTIALITY IN SEC.CONF=== " + confidentiality
            + "\nCONF-KEY=== " + confKeyS); //todo debug
        keyBytes = confKeyS.getBytes();
        cAlgorithm = confidentiality.split("/")[0];
    }

    public byte[] encrypt(byte[] input){
        switch (this.confidentiality){
            case "AES/GCM/NoPadding":
                return encryptMessageWithAES(input);
        }

        return "Not a known encryption algorithm".getBytes();
    }

    public byte[] decrypt(DataInputStream istream) throws IOException {
        switch (this.confidentiality){
            case "AES/GCM/NoPadding":
                int ctLength = istream.readInt();
                byte[] iv = istream.readNBytes(16);
                byte[] mBytes = new byte[ctLength];
                istream.readFully(mBytes);
                return decryptMessageWithAES(ctLength, iv, mBytes);
        }

        return "Not a known encryption algorithm".getBytes();
    }

    /**
     * Return encrypted message, in which the first 4 bytes is length of encrypted text
     * @param input
     * @return
     */
    private byte[] encryptMessageWithAES(byte[] input) {

        byte[] ivBytes = generateIv();

        SecretKeySpec key = new SecretKeySpec(this.keyBytes, cAlgorithm);
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, ivBytes);
        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        System.out.println("key   : " + Utils.toHex(keyBytes));

        System.out.println();
        System.out.println("input : " + Utils.toHex(input));

        // Cifrar
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e + " PROBLEM IN THE ENCRYPTION");
        }
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = 0;
        try {
            ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        }
        try {
            ctLength += cipher.doFinal(cipherText, ctLength);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        try {
            dataStream.writeInt(ctLength); // int value in first pos
            dataStream.write(ivBytes); // 16 bytes for IV
            dataStream.write(cipherText); // ciphertext afterwards
            dataStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e  + " PROBLEM IN THE ENCRYPTION IO EXEPT");
        }

        System.out.println("message with hash " + Arrays.hashCode(input) + " encrypted"); // TODO DEBUG

        return byteStream.toByteArray();
    }

    /**
     * Returns decrypted message, in which first 4 bytes are lenght of message
     * @param message
     * @return
     */
    private byte[] decryptMessageWithAES(int ctLength, byte[] ivBytes, byte[] message) {

        SecretKeySpec key = new SecretKeySpec(keyBytes, cAlgorithm);
        Cipher cipher;

        // rebuild the plaintext with lenght
        ByteArrayOutputStream plainTextByteStream = new ByteArrayOutputStream();
        DataOutputStream plainTextDataStream = new DataOutputStream(plainTextByteStream);

        try {
            cipher = Cipher.getInstance(confidentiality);

            System.out.println("ON DECRYPT: key   : " + Utils.toHex(keyBytes));

            System.out.println();
            System.out.println("input : " + Utils.toHex(message));

            // Decifrar

            ByteArrayInputStream byteStream = new ByteArrayInputStream(message);
            DataInputStream dataStream = new DataInputStream(byteStream);

            if (ctLength == -1)
                throw new ShortBufferException("Invalid ct length");

            byte[] cipherText = dataStream.readNBytes(ctLength);  // read ctLenght number of bytes
            dataStream.close();

            GCMParameterSpec ivSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = 0;


            ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);

            System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);

            plainTextDataStream.write(plainText); // ciphertext afterwards
            plainTextDataStream.close();

            System.out.println("message with hash " + Arrays.hashCode(plainText) + " decrypted ---"); // TODO DEBUG


        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("our decrypted message is: " + Arrays.toString(plainTextByteStream.toByteArray()));
        }

        return plainTextByteStream.toByteArray();

    }

    private static byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
