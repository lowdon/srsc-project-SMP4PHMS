package mchat.headers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Properties;

import static java.lang.Long.parseLong;

// CONTROL HEADER FOR SMP4PHMS Packet. To be sent in cleartext
public class SMP4PHMSHeader {

    public static int VERSION;
    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;
    public static byte[] HASH_NICKNAME; // = new byte[32]; always
    public static final String PROVIDER = "BC";
    public static byte[] headerBytes;

    public static int size;

    public SMP4PHMSHeader(String nickname, int opCode, long MAGIC_N) {
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
        HASH_NICKNAME = hash.digest(nickname.getBytes());

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        try {
            dataStream.writeLong(MAGIC_N);
            dataStream.writeInt(opCode);
            dataStream.writeInt(hash.getDigestLength());
            dataStream.write(HASH_NICKNAME);
            dataStream.writeInt(VERSION);
            dataStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        headerBytes = byteStream.toByteArray();
        size = headerBytes.length;
    }

    public byte[] getHeaderBytes(){
        return headerBytes;
    }


}
