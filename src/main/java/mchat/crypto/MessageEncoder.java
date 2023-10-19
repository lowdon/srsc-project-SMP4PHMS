package mchat.crypto;

import mchat.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Properties;

// this class will hold all crypto algorithms able to be called
public class MessageEncoder {

    //this will be the algorithm used for symmetric encryption. set it in the security.conf!!!
    private String confidentiality;
    private String cAlgorithm; //name of alg in confidentiality
    private String cMode;
    private String paddingType;
    private byte[] keyBytes;
    private MessageDigest hash;

    public MessageEncoder(){
        Security.addProvider(new BouncyCastleProvider());
        //conf file setup
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

        String[] confParts = confidentiality.split("/");
        cAlgorithm = confParts[0];
        cMode = confParts[1];
        paddingType = confParts[2];

        try {
            hash = MessageDigest.getInstance("SHA1", "BC"); // todo change to security.conf reading!!
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(byte[] input){

        byte[] encryption = new byte[0];

        //hash.update(input);

        switch (this.cAlgorithm){
            case "AES":
                encryption = encryptMessageWithAES(input);
                break;
            //case "AES/CCM/NoPadding":
//                encryption = encryptMessageWithAESCCM(input);
//                break;
//            case "AES/CTR/NoPadding":
//                encryption = encryptMessageWithAESCTR(input);
//                break;
//            case "DES/CBC/PKCS5Padding":
//                encryption = encryptMessageWithDES(input);
//                break;
//            case "RC6/CBC/PKCS5Padding":
//                encryption = encryptMessageWithRC6(input);
//                break;
//            case "ChaCha20":
//                encryption = encryptMessageWithChaCha20(input);
//                break;
//            case "RC4":
//                encryption = encryptMessageWithRC4(input);
//                break;
        }

        if(encryption.length == 0)
            return "Not a known encryption algorithm".getBytes();
        return encryption;
    }

    /**
     * Return encrypted message, in which the first 4 bytes is length of encrypted text
     * @param input
     * @return
     */
    private byte[] encryptMessageWithAES(byte[] input) {

        byte[] ivBytes;
        AlgorithmParameterSpec ivSpec;
        SecretKeySpec key = new SecretKeySpec(this.keyBytes, cAlgorithm);
        Cipher cipher;

        try {
            cipher = Cipher.getInstance(confidentiality);
            switch (cMode) {
                case "GCM":
                    ivBytes = generateIv(16);
                    ivSpec = new GCMParameterSpec(128, ivBytes);
                    break;
                case "CTR":
                    ivBytes = generateIv(16);
                    ivSpec = new IvParameterSpec(ivBytes);
                    break;
                case "CCM":
                    ivBytes = generateIv(13);
                    ivSpec = new IvParameterSpec(ivBytes);
                    break;
                default:
                    throw new NoSuchAlgorithmException();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e){
            throw new RuntimeException(e.getMessage());
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
        } catch (IllegalBlockSizeException | ShortBufferException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        try {
            dataStream.writeInt(ctLength); // int value in first pos
            dataStream.write(cipherText); // ciphertext afterwards
            dataStream.write(ivBytes); // 16 for gcm or ctr and 13 bytes for ccm IV
            dataStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage()  + " PROBLEM IN THE ENCRYPTION IO EXEPT");
        }

        System.out.println("message with hash " + Arrays.hashCode(input) + " encrypted"); // TODO DEBUG

        return byteStream.toByteArray();
    }

//    private byte[] encryptMessageWithRC4(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithChaCha20(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithAESCTR(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithAESCCM(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithRC6(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithDES(byte[] input) {
//    }

    public byte[] decrypt(DataInputStream istream) throws IOException {

        byte[] decryption = new byte[0];

        switch (this.cAlgorithm){
            case "AES":
                int ctLength = istream.readInt();
                byte[] ctBytes = istream.readNBytes(ctLength);

                //define iv based on mode
                byte[] ivBytes;
                if(cMode.equals("CCM")) {
                    ivBytes = new byte[13];
                } else { // we are in gcm or ctr mode
                    ivBytes = new byte[16];
                }
                istream.readFully(ivBytes);

                //define alg param spec
                AlgorithmParameterSpec ivSpec;
                if(cMode.equals("GCM"))
                    ivSpec = new GCMParameterSpec(128, ivBytes);
                else {
                    ivSpec = new IvParameterSpec(ivBytes);
                    //define hash for non auto-integrity algorithms
                    //hash.update(ctBytes); //todo tenho de ver onde posso colocar isto sem muita repeticao de codigo...
                }
                decryption = decryptMessageWithAES(ctLength, ctBytes, ivSpec);
                break;
//            case "DES/CBC/PKCS5Padding":
//                decryption = decryptMessageWithDES(input);
//                break;
//            case "RC6/CBC/PKCS5Padding":
//                decryption = decryptMessageWithRC6(input);
//                break;
//            case "ChaCha20":
//                decryption = decryptMessageWithChaCha20(input);
//                break;
//            case "RC4":
//                decryption = decryptMessageWithRC4(input);
//                break;
        }

        if(decryption.length == 0)
            return "Not a known encryption algorithm".getBytes();
        return decryption;
    }

//    private byte[] decryptMessageWithRC4(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithChaCha20(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithAESCTR(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithAESCCM(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithRC6(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithDES(byte[] input) {
//    }

    /**
     * Returns decrypted message, in which first 4 bytes are lenght of message
     * @param cipherText
     * @return
     */
    private byte[] decryptMessageWithAES(int ctLength, byte[] cipherText, AlgorithmParameterSpec ivSpec) {

        SecretKeySpec key = new SecretKeySpec(keyBytes, cAlgorithm);
        Cipher cipher;

        // rebuild the plaintext with lenght
        ByteArrayOutputStream plainTextByteStream = new ByteArrayOutputStream();
        DataOutputStream plainTextDataStream = new DataOutputStream(plainTextByteStream);

        try {
            cipher = Cipher.getInstance(confidentiality);

            System.out.println("ON DECRYPT: key   : " + Utils.toHex(keyBytes));

            System.out.println();
            System.out.println("input : " + Utils.toHex(cipherText));

            // Decifrar

            if (ctLength == -1)
                throw new ShortBufferException("Invalid ct length");

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

    private static byte[] generateIv(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
