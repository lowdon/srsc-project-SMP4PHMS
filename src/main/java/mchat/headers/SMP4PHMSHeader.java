package mchat.headers;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

// CONTROL HEADER FOR SMP4PHMS Packet. To be sent in cleartext
public class SMP4PHMSHeader {

    public static final byte VERSION = 0x04; // TODO TO BE READ FROM SECURITY CONF CHANGE!!!
    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;
    public static byte[] HASH_NICKNAME; // TODO TO BE READ FROM SECURITY CONF CHANGE!!!

    public SMP4PHMSHeader(String nickname) {
        Properties prop = new Properties();
        String fileName = "security.conf";
        try (FileInputStream fis = new FileInputStream(fileName)) {
            prop.load(fis);
        } catch (FileNotFoundException ex) {
             // FileNotFoundException catch is optional and can be collapsed
        } catch (IOException ignored) {
        }

        HASH_NICKNAME = nickname.getBytes();
        // prop.getProperty("VERSION")
    }
}
