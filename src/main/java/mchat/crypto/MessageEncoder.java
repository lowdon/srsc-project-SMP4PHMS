package mchat.crypto;

import mchat.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
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
    public final int VERSION;
    //this will be the algorithm used for symmetric encryption. set it in the security.conf!!!
    private String confidentiality;
    private String cAlgorithm; //name of alg in confidentiality
    private String cMode;
    private String paddingType;
    private byte[] keyBytes;
    private MessageDigest hash;
    private Mac hMac;
    private String macAlgorithm;
    private final boolean inHashMode;


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
        //verify integrity of conf file
        cAlgorithm = confParts[0];
        if (confParts.length == 3) {
            cMode = confParts[1];
            paddingType = confParts[2];
        }
        else {
            cMode = "";
            paddingType = "";
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
        VERSION = Integer.parseInt(props.getProperty("VERSION"));
    }

    public byte[] encrypt(byte[] input){
        //debug
        System.out.println("Encrypt::: key   : " + Utils.toHex(keyBytes));

        System.out.println();
        System.out.println("input : " + Utils.toHex(input));
        //end debug

        try {

            byte[] encryption = new byte[0];

            //todo must implement verification for prefered hashmode
            if (inHashMode)
                hash.update(input);

            switch (this.cAlgorithm) {
                case "AES":
                    encryption = encryptMessageWithAES(input);
                    break;
                case "ChaCha20":
                    encryption = encryptMessageWithChaCha20(input);
                    break;
//            case "DES/CBC/PKCS5Padding":
//                encryption = encryptMessageWithDES(input);
//                break;
//            case "RC6/CBC/PKCS5Padding":
//                encryption = encryptMessageWithRC6(input);
//                break;
//            case "RC4":
//                encryption = encryptMessageWithRC4(input);
//                break;
            }

            if (encryption.length == 0)
                return "Not a known encryption algorithm".getBytes();
            else
                System.out.println("encrypted successfully ---"); // TODO DEBUG

            return encryption;
        }
        catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("ENCRYPT FAIL: " + e.getMessage());
        }
    }

    /**
     * Return encrypted message, in which the first 4 bytes is length of encrypted text
     * @param input
     * @return
     */
    private byte[] encryptMessageWithAES(byte[] input) throws IOException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchPaddingException, NoSuchProviderException {

        byte[] ivBytes = new byte[0];
        AlgorithmParameterSpec ivSpec = null;
        SecretKeySpec key = new SecretKeySpec(this.keyBytes, cAlgorithm);
        Cipher cipher;
        Key hMacKey = null;

        if(!inHashMode && !cMode.equals("GCM"))
            hMacKey = new SecretKeySpec(key.getEncoded(), macAlgorithm);

        boolean needsIv = true;

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

        // Cifrar
        if(needsIv)
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        else // ecb mode
            cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText;

        if(cMode.equals("GCM"))
            cipherText = new byte[cipher.getOutputSize(input.length)];
        else if(inHashMode) //here we increase the buffer size to hold the hash
            cipherText = new byte[cipher.getOutputSize(input.length + hash.getDigestLength() )];
        else // hmac mode is enabled
            cipherText = new byte[cipher.getOutputSize(input.length + hMac.getMacLength() )];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        if(cMode.equals("GCM") || cMode.equals("CCM") ||cMode.equals("OCB") ) //does not need hash
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

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeInt(ctLength); // int value in first pos
        dataStream.write(cipherText); // ciphertext afterwards
        if(needsIv)
            dataStream.write(ivBytes); // 16 bytes for gcm or ctr and 13 bytes for ccm's IV
        dataStream.close();

        return byteStream.toByteArray();
    }

    private byte[] encryptMessageWithChaCha20(byte[] input) throws InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, IOException {
        byte[] ivBytes = generateIv(12);
        int counter = SecureRandom.getInstanceStrong().nextInt();
        SecretKeySpec key = new SecretKeySpec(this.keyBytes, cAlgorithm);
        Cipher cipher = Cipher.getInstance(cAlgorithm);

        // Create ChaCha20ParameterSpec
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(ivBytes, counter);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "ChaCha20");

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(input);

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeInt(cipherText.length); // int value in first pos
        dataStream.write(cipherText); // ciphertext afterwards
        dataStream.write(ivBytes);
        dataStream.writeInt(counter);
        dataStream.close();

        System.out.println("cipher: " + Utils.toHex(cipherText, cipherText.length) + " bytes: " + cipherText.length);//debug

        return byteStream.toByteArray();
    }

//    private byte[] encryptMessageWithRC4(byte[] input) {
//    }
//
//
//    private byte[] encryptMessageWithRC6(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithDES(byte[] input) {
//    }

    public String decrypt(DataInputStream istream){
        String message = null;

        try{
            int msgVersion = istream.readInt() - '0';
            System.out.println("receivedMsgVersion: " + msgVersion +  " confVERSION: " + VERSION);
            if(msgVersion == VERSION){
                message = new String(startDecrypt(istream)); // TODO here istream.readUTF should be encapsulated by some decrypt() function
            }
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("DECRYPT FAIL: " + e.getMessage());
        }

        return message;
    }
    private byte[] startDecrypt(DataInputStream istream) throws IOException,
            InvalidAlgorithmParameterException, ShortBufferException,
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, NoSuchProviderException, InvalidKeyException {

        byte[] decryption = new byte[0];
        byte[] ctBytes = new byte[0];
        byte[] ivBytes;

        System.out.println("\nDecrypt::: key   : " + Utils.toHex(keyBytes));
        System.out.println();

        switch (this.cAlgorithm){
            case "AES":
                ctBytes = istream.readNBytes(istream.readInt());

                //define iv based on mode
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
                decryption = decryptMessageWithAES(ctBytes.length, ctBytes, ivSpec);
                break;
            case "ChaCha20":
                ctBytes = istream.readNBytes(istream.readInt()); // ciphertext afterwards
                ChaCha20ParameterSpec chaSpec = new ChaCha20ParameterSpec(istream.readNBytes(12),
                        istream.readInt());
                decryption = decryptMessageWithChaCha20(ctBytes, chaSpec);
                break;

//            case "DES/CBC/PKCS5Padding":
//                decryption = decryptMessageWithDES(input);
//                break;
//            case "RC6/CBC/PKCS5Padding":
//                decryption = decryptMessageWithRC6(input);
//                break;
//            case "RC4":
//                decryption = decryptMessageWithRC4(input);
//                break;
        }

        
        System.out.println("cipher : " + Utils.toHex(ctBytes));
        System.out.println("plain : " + Utils.toHex(decryption));

        if(decryption.length == 0)
            return "Not a known encryption algorithm".getBytes();
        else
            System.out.println("decrypted successfully ---");

        return decryption;
    }

    /**
     * Decryption with ChaCha20 stream cipher
     * @param cipherText
     * @param chaSpec
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    private byte[] decryptMessageWithChaCha20(byte[] cipherText, AlgorithmParameterSpec chaSpec)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        Cipher cipher = Cipher.getInstance(confidentiality);
        SecretKeySpec keySpec = new SecretKeySpec(this.keyBytes, cAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, chaSpec);

        return cipher.doFinal(cipherText);
    }

    /**
     * Returns decrypted message, in which first 4 bytes are lenght of message
     * @param cipherText
     * @return
     */
    private byte[] decryptMessageWithAES(int ctLength, byte[] cipherText, AlgorithmParameterSpec ivSpec)
            throws ShortBufferException, NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException {

        SecretKeySpec key = new SecretKeySpec(keyBytes, cAlgorithm);
        Cipher cipher;

        Key hMacKey = null;

        if(!inHashMode && !cMode.equals("GCM"))
            hMacKey = new SecretKeySpec(key.getEncoded(), macAlgorithm);

        // rebuild the plaintext with lenght
        ByteArrayOutputStream plainTextByteStream = new ByteArrayOutputStream();
        DataOutputStream plainTextDataStream = new DataOutputStream(plainTextByteStream);

        cipher = Cipher.getInstance(confidentiality, PROVIDER);

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
        if( !cMode.equals("GCM") && !cMode.equals("CCM") && !cMode.equals("OCB") ){
            messageLength = getMsgLenAndCheckHashMac(ptLength, plainText, hMacKey);

            byte[] messageText = new byte[messageLength];
            System.arraycopy(plainText, 0, messageText, 0, messageLength); // copies messageText from plain to msgText
            plainTextDataStream.write(messageText);


        } else {
            plainTextDataStream.write(plainText); // ciphertext afterwards
            System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
        }
        plainTextDataStream.close();

        return plainTextByteStream.toByteArray();
    }

    private int getMsgLenAndCheckHashMac(int ptLength, byte[] plainText, Key hMacKey) throws InvalidKeyException {
        int messageLength;
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
        return messageLength;
    }
//
//    private byte[] decryptMessageWithRC4(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithRC6(byte[] input) {
//    }
//
//    private byte[] decryptMessageWithDES(byte[] input) {
//    }

    private static byte[] generateIv(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public boolean compareHashes(String username, byte[] h2){
        try {
            hash = MessageDigest.getInstance("SHA256", PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        hash.update(username.getBytes());
        byte[] h1 = hash.digest();

        if(Arrays.equals(h1, h2))
            return true;
        return false;
    }

}
