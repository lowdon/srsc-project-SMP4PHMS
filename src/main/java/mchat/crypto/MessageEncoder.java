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
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

// this class will hold all crypto algorithms able to be called
public class MessageEncoder {

    public static final String PROVIDER = "BC";
    public static final int GCM_T_LEN = 128;
    //this will be the algorithm used for symmetric encryption. set it in the security.conf!!!
    private String confidentiality;
    private String cAlgorithm; //name of alg in confidentiality
    private String cMode;
    private String paddingType;
    private byte[] keyBytes;
    private MessageDigest hash;
    private Mac hMac;
    private String macAlgorithm;
    boolean inHashMode;

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
        try { //verify integrity of conf file
            if (confParts.length != 3)
                throw new InvalidPropertiesFormatException("Invalid conf file setup");
            cAlgorithm = confParts[0];
            cMode = confParts[1];
            paddingType = confParts[2];
        } catch (InvalidPropertiesFormatException e){
            throw new RuntimeException(e);
        }

        //check if we are in hash mode or HMAC mode
        String enableHMacS = props.getProperty("ENABLE_HMAC");
        if(enableHMacS.equals("1"))
            inHashMode = false;
        else
            inHashMode = true;

        if(inHashMode) {
            try {
                hash = MessageDigest.getInstance(props.getProperty("HASH"), PROVIDER); // todo change to security.conf reading!!
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
        } else {
            try {
                macAlgorithm = props.getProperty("MACALGORITHM");
                hMac = Mac.getInstance(macAlgorithm, PROVIDER);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public byte[] encrypt(byte[] input){
        try {

            byte[] encryption = new byte[0];

            //todo must implement verification for prefered hashmode
            if (inHashMode)
                hash.update(input);


            switch (this.cAlgorithm) {
                case "AES":
                    encryption = encryptMessageWithAES(input);
                    break;
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

            if (encryption.length == 0)
                return "Not a known encryption algorithm".getBytes();
            return encryption;
        }catch (Exception e){
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * Return encrypted message, in which the first 4 bytes is length of encrypted text
     * @param input
     * @return
     */
    private byte[] encryptMessageWithAES(byte[] input) {

        byte[] ivBytes = new byte[0];
        AlgorithmParameterSpec ivSpec = null;
        SecretKeySpec key = new SecretKeySpec(this.keyBytes, cAlgorithm);
        Cipher cipher;
        Key hMacKey = null;

        if(!inHashMode && !cMode.equals("GCM"))
            hMacKey = new SecretKeySpec(key.getEncoded(), macAlgorithm);

        boolean needsIv = true;

        try {
            cipher = Cipher.getInstance(confidentiality, PROVIDER);
            switch (cMode) {
                case "GCM":
                    ivBytes = generateIv(16);
                    ivSpec = new GCMParameterSpec(GCM_T_LEN, ivBytes);
                    break;
                case "CTR":
                    ivBytes = generateIv(16);
                    ivSpec = new IvParameterSpec(ivBytes);
                    break;
                case "CCM":
                    ivBytes = generateIv(13);
                    ivSpec = new IvParameterSpec(ivBytes);
                    break;
                case "ECB":
                    needsIv = false;
                    break;
                default:
                    throw new NoSuchAlgorithmException();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e){
            throw new RuntimeException(e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        System.out.println("key   : " + Utils.toHex(keyBytes));

        System.out.println();
        System.out.println("input : " + Utils.toHex(input));

        // Cifrar
        try {
            if(needsIv)
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            else // ecb mode
                cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e + " PROBLEM IN THE ENCRYPTION");
        }

        //todo example for hash. there will be then hmac mac hash
        byte[] cipherText = new byte[0];

        if(cMode.equals("GCM"))
            cipherText = new byte[cipher.getOutputSize(input.length)];
        else if(inHashMode) //here we increase the buffer size to hold the hash
            cipherText = new byte[cipher.getOutputSize(input.length + hash.getDigestLength() )];
        else // hmac mode is enabled
            cipherText = new byte[cipher.getOutputSize(input.length + hMac.getMacLength() )];

        int ctLength = 0;
        try {
            ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        }
        try {
            if(cMode.equals("GCM")) //gcm does not need hash
                ctLength += cipher.doFinal(cipherText, ctLength); // this is without hash in encrypted message
            else if (inHashMode){
                byte[] hashDigest = hash.digest();
                ctLength += cipher.doFinal(hashDigest, 0, hash.getDigestLength(), cipherText, ctLength);
                System.out.println("message with hash " + Utils.toHex(hashDigest)); // todo debug
            } else{
                hMac.init(hMacKey);
                hMac.update(input);
                ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);
                System.out.println("message with HMAC " + Utils.toHex(hMac.doFinal())); // todo debug
            }
        } catch (IllegalBlockSizeException | ShortBufferException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        try {
            dataStream.writeInt(ctLength); // int value in first pos
            dataStream.write(cipherText); // ciphertext afterwards
            if(needsIv)
                dataStream.write(ivBytes); // 16 bytes for gcm or ctr and 13 bytes for ccm's IV
            dataStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage()  + " PROBLEM IN THE ENCRYPTION IO EXEPT");
        }

        System.out.println("encrypted successfully ---"); // TODO DEBUG

        return byteStream.toByteArray();
    }

//    private byte[] encryptMessageWithRC4(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithChaCha20(byte[] input) {
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
                if(!cMode.equals("ECB")) //if ecb there is no iv to read
                    istream.readFully(ivBytes);

                //define alg param spec
                AlgorithmParameterSpec ivSpec = null;
                if(cMode.equals("GCM"))
                    ivSpec = new GCMParameterSpec(GCM_T_LEN, ivBytes);
                else if(cMode.equals("CCM") || cMode.equals("CTR")){
                    ivSpec = new IvParameterSpec(ivBytes);
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

        Key hMacKey = null;

        if(!inHashMode && !cMode.equals("GCM"))
            hMacKey = new SecretKeySpec(key.getEncoded(), macAlgorithm);

        // rebuild the plaintext with lenght
        ByteArrayOutputStream plainTextByteStream = new ByteArrayOutputStream();
        DataOutputStream plainTextDataStream = new DataOutputStream(plainTextByteStream);

        try {
            cipher = Cipher.getInstance(confidentiality, PROVIDER);

            System.out.println("\nON DECRYPT: key   : " + Utils.toHex(keyBytes));

            System.out.println();
            System.out.println("input : " + Utils.toHex(cipherText));

            // Decifrar

            if (ctLength == -1)
                throw new ShortBufferException("Invalid ct length");

            if(ivSpec == null) // ecb mode
                cipher.init(Cipher.DECRYPT_MODE, key); // needs 18byte key
            else
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = 0;

            ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);

            //message integrity verification with hash, will not be used for GCM or other autheticated modes
            int messageLength = -1;
            if(!cMode.equals("GCM")){
                if(inHashMode) {
                    messageLength = ptLength - hash.getDigestLength();
                    hash.update(plainText, 0, messageLength);

                    byte[] messageHash = new byte[hash.getDigestLength()];
                    System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

                    byte[] hashDigest = hash.digest();
                    //THIS WILL PRINT IF HASHES MATCH OR NOT!!!
                    System.out.println("plain : " + Utils.toString(plainText, messageLength) + "\nhashverified: " +
                            MessageDigest.isEqual(hashDigest, messageHash));
                    System.out.println("message with original hash: " + Utils.toHex(messageHash) +
                            "\ncalculated hash after decryption: " + Utils.toHex(hashDigest));
                } else { // HMAC mode is enabled
                    messageLength = ptLength - hMac.getMacLength();
                    hMac.init(hMacKey);
                    hMac.update(plainText, 0, messageLength);

                    byte[] messageHash = new byte[hMac.getMacLength()];
                    System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

                    //THIS WILL PRINT IF HMAC MATCH OR NOT!!!
                    System.out.println("plain : " + Utils.toString(plainText, messageLength) + "\nHMACverified: " +
                            MessageDigest.isEqual(hMac.doFinal(), messageHash));
                    System.out.println("message with HMAC " + Utils.toHex(hMac.doFinal()));
                }

                byte[] messageText = new byte[messageLength];
                System.arraycopy(plainText, 0, messageText, 0, messageLength); // copies messageText from plain to msgText
                plainTextDataStream.write(messageText);


            } else {
                plainTextDataStream.write(plainText); // ciphertext afterwards
                System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
            }
            plainTextDataStream.close();

            //output
            System.out.println("decrypted successfully ---");

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("DECRYPT FAIL - our decrypted message is: " +
                    Arrays.toString(plainTextByteStream.toByteArray()));
        }

        return plainTextByteStream.toByteArray();
    }

    private static byte[] generateIv(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
