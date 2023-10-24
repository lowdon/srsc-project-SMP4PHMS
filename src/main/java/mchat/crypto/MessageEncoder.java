package mchat.crypto;

import mchat.utils.Utils;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// this class will hold all crypto algorithms able to be called
public class MessageEncoder {

    public static final String PROVIDER = "BC";
    public static final int GCM_T_LEN = 128;
    public static int ASM_KEYSIZE = 1024;
    public final int VERSION;
    //this will be the algorithm used for symmetric encryption. set it in the security.conf!!!
    private String clientName;
    private String confidentiality;
    private String cAlgorithm; //name of alg in confidentiality
    private String cMode;
    private String paddingType;
    private byte[] keyBytes;
    private MessageDigest hash;
    private Mac hMac;
    private String macAlgorithm;
    private final boolean inHashMode;
    private String asymmetricConf;
    private String asymmetricAlg;
    public PublicKey pubKey;
    public PrivateKey privKey;
    private HashMap<String, PublicKey> pubKeyMap;
    //private HashMap<String, PublicKey> privKeyMap;
    private String sigAlg;

    public MessageEncoder(String username){
        Security.addProvider(new BouncyCastleProvider());
        clientName = username;
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

        //HashSetup
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

        //Asymmetric setup
        asymmetricConf = props.getProperty("ASYMMETRIC-ALG");
        asymmetricAlg = asymmetricConf.split("/")[0];
        try {
            setAsmKeyPair();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        ASM_KEYSIZE = Integer.parseInt(props.getProperty("ASM-KEYSIZE"));

        pubKeyMap = new HashMap<>();
        //privKeyMap = new HashMap<>();
        sigAlg = props.getProperty("SIGNATURE-ALG");

        //keystore config
        try {
            readAllFromKeystore(props.getProperty("KEYSTORE-DIR"));
        } catch (NoSuchProviderException | UnrecoverableKeyException | CertificateException | IOException | KeyStoreException |
                 NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
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
        SecretKeySpec key = new SecretKeySpec(keyBytes, cAlgorithm);
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
        SecretKeySpec key = new SecretKeySpec(keyBytes, cAlgorithm);
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
//    private byte[] encryptMessageWithRC6(byte[] input) {
//    }
//
//    private byte[] encryptMessageWithDES(byte[] input) {
//    }

    public String decrypt(String username, byte[] userHash, DataInputStream istream){
        String message = null;

        try{
            int msgVersion = istream.readInt() - '0';
            System.out.println("receivedMsgVersion: " + msgVersion +  " confVERSION: " + VERSION);
            int signLen = istream.readInt();
            verifySign(username, istream.readNBytes(signLen));

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
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, cAlgorithm);
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

    private void setAsmKeyPair() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");
        System.out.println("Set keypairgen to: " + "DSA");
        // Keypair generation

        g.initialize(ASM_KEYSIZE, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        pubKey = pair.getPublic();
        privKey = pair.getPrivate();
    }

    /**
     * Gets pub key from userhash or adds it to pubkeymap for later usage
     * @param userHash
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private PublicKey setAsmSignKeyPair(byte[] userHash) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");
        System.out.println("Set keypairgen to: " + "DSA");
        // Keypair generation
        if(pubKeyMap.containsKey(Arrays.toString(userHash)))
            return pubKeyMap.get(Arrays.toString(userHash));

        g.initialize(ASM_KEYSIZE, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        pubKey = pair.getPublic();
        privKey = pair.getPrivate();

        pubKeyMap.put(Arrays.toString(userHash), pubKey);
        System.out.println("sign::: added pubkey of userhash: " + Arrays.toString(userHash));
        return pubKey;
    }

    //Asymmetric encryption

    /**
     * This gets the symmetric key, encrypted with asymmetric encryption for sharing. Decrypt with
     * @return the symmetric key, encrypted with asymmetric encryption for sharing
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public byte[] shareSymKey() throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return encryptAsymmetric(keyBytes);
    }

    /**
     * Encrypts a byte array with any input byte array
     * @param input
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encryptAsymmetric(byte[] input) throws NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(asymmetricConf, PROVIDER);
        SecureRandom random = new SecureRandom();

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input); // send keybytes
        System.out.println("cipher: " + Utils.toHex(cipherText));

        return cipherText;
    }

    public byte[] decryptAsymmetric(byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(asymmetricConf, PROVIDER);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(input);
        System.out.println("plain : " + Utils.toHex(plainText));

        return plainText;
    }

    public byte[] sign(byte[] input, byte[] username) {
        try {
            Signature signature = Signature.getInstance(sigAlg);
            //setAsmSignKeyPair(username); //defines pub and priv key
            signature.initSign(privKey); // assumes we have read all certs from keystore!!!

            signature.update(input);
            byte[] sign = signature.sign();
            System.out.println("Signature (hex)   : " + Utils.toHex(sign));
            System.out.println("Sig. Size (bytes) : " + sign.length);

            ByteArrayOutputStream plainTextByteStream = new ByteArrayOutputStream();
            DataOutputStream plainTextDataStream = new DataOutputStream(plainTextByteStream);

            plainTextDataStream.writeInt(sign.length);
            plainTextDataStream.write(sign);
            plainTextDataStream.writeInt(input.length);
            plainTextDataStream.write(input);

            return plainTextByteStream.toByteArray();

        } catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("HERE!!!  " + e);
        }
    }

    public void verifySign(String username, byte[] signedBytes) {
        try {
            ByteArrayInputStream plainTextByteStream = new ByteArrayInputStream(signedBytes);
            DataInputStream plainTextDataStream = new DataInputStream(plainTextByteStream);

            byte[] sign = plainTextDataStream.readNBytes(plainTextDataStream.readInt());
            byte[] origMessage = plainTextDataStream.readNBytes(plainTextDataStream.readInt());
            plainTextDataStream.close();
            plainTextByteStream.close();

            System.out.println("verifysign::: trying to get pubkey of user: " + username);
            Signature signature = Signature.getInstance(sigAlg);
            PublicKey currPubKey = pubKeyMap.get(username);
            signature.initVerify(currPubKey);
            signature.update(origMessage);
            if (signature.verify(sign))
            {
                System.out.println("Assinatura validada - reconhecida");
            }
            else
            {
                System.out.println("Assinatura nao reconhecida");
            }
            System.out.println("Signature (hex)   : " + Utils.toHex(sign));
            System.out.println("Sig. Size (bytes) : " + sign.length);


            //return signature.sign();

//            Cipher cipher = Cipher.getInstance(asymmetricConf, PROVIDER);
//            SecureRandom random = new SecureRandom();
//
//            Key selectKey = null;
//            switch (asymmetricAlg){
//                case "RSA":
//                    selectKey = pubKeyMap.get(userHash); // get public key from sender
//                    cipher.init(Cipher.DECRYPT_MODE, selectKey); //uses pub key
//                    break;
//                case "ELGamal":
//                    //ElGamalPublicKeyParameters elPubKeyParams = new ElGamalPublicKeyParameters()
//                    selectKey = pubKeyMap.get(userHash); // get public key from sender
//                    cipher.init(Cipher.DECRYPT_MODE,selectKey, random); //uses priv key
//                    break;
//            }
//
//            // Encrypt
//
//            byte[] cipherText = cipher.doFinal(input); // send keybytes
        } catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


    public byte[] getMyPublicKey() {
        return pubKey.getEncoded();
    }

    public void addNewPublicKey(byte[] userHash, String asymAlg, byte[] pubKeyBytes)
            throws Exception {
        if(!pubKeyMap.containsKey(Arrays.toString(userHash))) //todo may have problems with hash collisions, will have to solve later
            pubKeyMap.put(Arrays.toString(userHash), getKeyFromByteArray(pubKeyBytes, asymAlg));
    }

    public PublicKey getKeyFromByteArray(byte[] pubKeyBytes, String asymAlg) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PublicKey publicKey =
                KeyFactory.getInstance(asymAlg).generatePublic(new X509EncodedKeySpec(pubKeyBytes));
//        KeySpec spec = new RSAPublicKeySpec(pubKeyBytes);
//        KeyFactory kf = KeyFactory.getInstance(asymAlg);
//        return kf.generatePublic(spec);
        return publicKey;
    }

    public String getAsymmetricAlg(){
        return asymmetricAlg;
    }

    private KeyPair readKeyPairFromKeystore(String dir, String fileEntryName) throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException {
        String username = fileEntryName.split(".jks")[0];
        FileInputStream is = new FileInputStream(dir + "/" + fileEntryName);
        System.out.println("DEFAULT KEYSTORE: " + KeyStore.getDefaultType());
        KeyStore keystore = KeyStore.getInstance("jks");
        char[] pwd = "password".toCharArray();
        keystore.load(is, pwd);

        Key key = keystore.getKey(username, pwd);
        if (key instanceof PrivateKey) {

            X509Certificate  cert = (X509Certificate) keystore.getCertificate(username);
            // Get now public key
            PublicKey publicKey = cert.getPublicKey();
            // Get the KeyPair
            KeyPair kp= new KeyPair(publicKey, (PrivateKey) key);
            // Get again the Public and Private Key from the KeyPair
            if(!pubKeyMap.containsKey(username)) // do not add repeat ones
                pubKeyMap.put(username, kp.getPublic());
            if(username.equals(clientName)) { // cert matches current user
                pubKey = kp.getPublic();
                privKey = kp.getPrivate(); // we set our privatekey
            }
            return kp;
        }
        throw new CertificateException("Error::: Could not read keypair from cert.");
    }

    private Set<String> listFilesUsingJavaIO(String dir) {
        return Stream.of(new File(dir).listFiles())
                .filter(file -> !file.isDirectory())
                .map(File::getName)
                .collect(Collectors.toSet());
    }

    /**
     * Reads all cert files in "./keystore" to get public keys, stores them in memory
     * @throws UnrecoverableKeyException
     * @throws CertificateException
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    public void readAllFromKeystore(String dir) throws UnrecoverableKeyException,
            CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {
        Set<String> files = listFilesUsingJavaIO(dir);
        for (String fileEntry : files) {
            System.out.println("CERTIFICATE FOUND: " + fileEntry);
            readKeyPairFromKeystore(dir, fileEntry);
        }
    }
}
