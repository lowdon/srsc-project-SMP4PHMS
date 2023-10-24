package mchat.headers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.util.Properties;

import static java.lang.Long.parseLong;

// CONTROL HEADER FOR SMP4PHMS Packet. To be sent in cleartext
public class SMP4PHMSHeader {

    public static int VERSION;
    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

    public static String username;
    public static byte[] userHash; // = new byte[32]; always
    public static final String PROVIDER = "BC";
    public static byte[] headerBytes;

    public static int size;
    public byte[] pubKeyShareBytes;

    public SMP4PHMSHeader(String nickname, int opCode, long MAGIC_N, byte[] pubKeyShare, String asymAlg) {
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
        VERSION = props.getProperty("VERSION").getBytes()[0];
        MessageDigest hash = null; // todo change to security.conf reading!!
        try {
            hash = MessageDigest.getInstance("SHA256", PROVIDER); //may fail??
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        userHash = hash.digest(nickname.getBytes());


        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        try {
            dataStream.writeLong(MAGIC_N);
            dataStream.writeInt(opCode);
            dataStream.writeInt(hash.getDigestLength());
            dataStream.write(userHash);
            if(opCode == 1) { //on join, share asym keys
                pubKeyShareBytes = pubKeyShare;
                dataStream.writeUTF(asymAlg);
                dataStream.writeInt(pubKeyShare.length);
                dataStream.write(pubKeyShare);
            } else if(opCode == 3){
                dataStream.writeUTF(nickname);
            }
            dataStream.writeInt(VERSION);
            dataStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        headerBytes = byteStream.toByteArray();
        size = headerBytes.length;
        username = nickname;
    }

    public byte[] getHeaderBytes(){
        return headerBytes;
    }

    public byte[] getUserHash(){
        return userHash;
    }


}
