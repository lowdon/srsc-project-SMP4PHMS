package mchat.datagrams;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class SMP4PHMSPacket {

    private final byte[] packet;
    public SMP4PHMSPacket(byte[] header, byte[] message) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        try {
            dataStream.write(header);
            dataStream.write(message);
            dataStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        packet = byteStream.toByteArray();
    }

    public byte[] getPacket(){
        return packet;
    }
}
