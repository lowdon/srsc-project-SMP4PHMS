package mchat.crypto;

import mchat.utils.Utils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

// this class will hold all crypto algorithms able to be called
public class MessageEncoder {

    public static byte[] encrypt(String confidentiality, byte[] input){
        switch (confidentiality){
            case "AES/GCM/NoPadding":
                return encryptMessageWithAES(input, "".getBytes());
        }

        return "Not a known encryption algorithm".getBytes();
    }

    public static byte[] decrypt(String confidentiality, DataInputStream istream) throws IOException {
        switch (confidentiality){
            case "AES/GCM/NoPadding":
                int ctLength = istream.readInt();
                byte[] iv = istream.readNBytes(16);
                byte[] mBytes = new byte[ctLength];
                istream.readFully(mBytes);
                return decryptMessageWithAES(ctLength, iv, mBytes, "".getBytes());
        }

        return "Not a known encryption algorithm".getBytes();
    }

    /**
     * Return encrypted message, in which the first 4 bytes is length of encrypted text
     * @param input
     * @param keyBytes
     * @return
     */
    private static byte[] encryptMessageWithAES(byte[] input, byte[] keyBytes) {

        keyBytes = new byte[] { // TODO TEMPORARY!!! DELETE
                0x01, 0x23, 0x45, 0x67, 0x09, 0x0a, 0x5c, (byte)0xef,
                0x01, 0x23, 0x45, 0x67, (byte)0x89, 0x07, 0x0d, (byte)0xcf
        };

        byte[] ivBytes = generateIv();

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, ivBytes);
        Cipher cipher = null;

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
        //return cipherText;  //todo if number of bytes is needed, use line above
    }

    /**
     * Returns decrypted message, in which first 4 bytes are lenght of message
     * @param message
     * @param keyBytes
     * @return
     */
    private static byte[] decryptMessageWithAES(int ctLength, byte[] ivBytes, byte[] message, byte[] keyBytes) {

        keyBytes = new byte[]{ // TODO TEMPORARY!!! DELETE
                0x01, 0x23, 0x45, 0x67, 0x09, 0x0a, 0x5c, (byte) 0xef,
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, 0x07, 0x0d, (byte) 0xcf
        };


        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        //IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = null;

        // rebuild the plaintext with lenght
        ByteArrayOutputStream plainTextByteStream = new ByteArrayOutputStream();
        DataOutputStream plainTextDataStream = new DataOutputStream(plainTextByteStream);

        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");

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
