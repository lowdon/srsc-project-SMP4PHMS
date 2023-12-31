package mchat.sockets;// SecureMulticastChat.java
// Represents the Multicast Chat/Messaging Protocol
// As you can see, the used Multicast Communication Channel
// is not secure .... Messages flow as plaintext messages
// You can see that if an adversary inspects traffic w/ a tool such as Wireshark,
// she/he know everything the users are saying in the Chat ...
// Also ... she/he can also operate as a Man In The Middle .... and it is easy
// for her/him to cheat/fool the users

import mchat.crypto.MessageEncoder;
import mchat.datagrams.SMP4PHMSPacket;
import mchat.headers.SMP4PHMSHeader;
import mchat.utils.Utils;

import java.io.*;
import java.net.*;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class SecureMulticastChat extends Thread {

    // Definition of opcode for JOIN type
    public static final int JOIN = 1;

    // Definition of opcode for LEAVE type
    public static final int LEAVE = 2;

    // Definition of opcode for a regular message type (sent/received)
    public static final int MESSAGE = 3;

    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

    // Timeout for sockets
    public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

    // Multicast socket used to send and receive multicast protocol PDUs
    protected MulticastSocket msocket;

    // Username / User-Nick-Name in Chat
    protected String username;

    // Grupo IP Multicast used
    protected InetAddress group;

    // Listener for Multicast events that must be processed
    protected MulticastChatEventListener listener;

    // Control  - execution thread

    protected boolean isActive;

    private MessageEncoder messageEncoder;

    // Multicast Chat-Messaging
    public SecureMulticastChat(String username, InetAddress group, int port,
                               int ttl, MulticastChatEventListener listener) throws IOException {

        this.username = username;
        this.group = group;
        this.listener = listener;
        isActive = true;

        messageEncoder = new MessageEncoder(username);

        // create & configure multicast socket

        msocket = new MulticastSocket(port);
        msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
        msocket.setTimeToLive(ttl);
        msocket.joinGroup(group);

        // start receive thread and send multicast join message
        start();
        sendJoin();
    }

    /**
     * Sent notification when user wants to leave the Chat-messaging room
     */

    public void terminate() throws IOException {
        isActive = false;
        sendLeave();
    }

    // to process error message
    protected void error(String message) {
        System.err.println(new java.util.Date() + ": SecureMulticastChat: "
                + message);
    }

    // Send a JOIN message
    //
    protected void sendJoin() throws IOException {
        sendJoinOrLeave(JOIN);
    }

    // Process recived JOIN message
    //
    protected void processJoin(DataInputStream istream, InetAddress address,
                               int port) throws IOException {
        int hashLen = istream.readInt();
        byte[] userHash = istream.readNBytes(hashLen);
        String asymAlg = istream.readUTF();
        System.out.println("ASYMALG: " + asymAlg);
        try {
            byte[] pKey = istream.readNBytes(istream.readInt()); // todo will not be used
            listener.chatParticipantJoined(Utils.toHex(userHash), address, port);
        } catch (Throwable e) { e.getMessage(); }
    }

    // Send LEAVE
    protected void sendLeave() throws IOException {
        sendJoinOrLeave(LEAVE);
    }

    // Processes a multicast chat LEAVE and notifies listeners

    protected void processLeave(DataInputStream istream, InetAddress address,
                                int port) throws IOException {
        int hashLen = istream.readInt();
        String userHash = Utils.toHex(istream.readNBytes(hashLen));

        try {
            listener.chatParticipantLeft(userHash, address, port);
        } catch (Throwable e) {}
    }

    // Send message to the chat-messaging room
    //
    public void sendMessage(String message) throws IOException {
        SMP4PHMSHeader header = new SMP4PHMSHeader(username, MESSAGE, CHAT_MAGIC_NUMBER, null,
                null);
        SMP4PHMSPacket sPacket = new SMP4PHMSPacket( header.getHeaderBytes(),
                messageEncoder.sign(header.getHeaderBytes(), username.getBytes()), messageEncoder.encrypt(message.getBytes()), true);
        DatagramPacket packet = new DatagramPacket(sPacket.getPacket(), sPacket.getPacket().length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }


    // Process a received message  //
    //
    protected void processMessage(DataInputStream istream,
                                  InetAddress address,
                                  int port) throws IOException {
        int hashLen = istream.readInt();
        byte[] userHash = istream.readNBytes(hashLen);
        String message = messageEncoder.decrypt(istream.readUTF(), userHash, istream);
        listener.chatMessageReceived(Utils.toHex(userHash), address, port, message);
    }

    private void sendJoinOrLeave(int opCode) throws IOException {
        SMP4PHMSHeader header = new SMP4PHMSHeader(username, opCode, CHAT_MAGIC_NUMBER,
                messageEncoder.getMyPublicKey(), messageEncoder.getAsymmetricAlg());
        DatagramPacket packet = new DatagramPacket(header.getHeaderBytes(), header.getHeaderBytes().length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }

    // Loop:
    // reception and demux received datagrams to process,
    // according with message types and opcodes
    //
    public void run() {
        byte[] buffer = new byte[65508];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        while (isActive) {
            try {

                // Set buffer to receive UDP packet
                packet.setLength(buffer.length);
                msocket.receive(packet);

                // Read received datagram

                DataInputStream istream =
                        new DataInputStream(new ByteArrayInputStream(packet.getData(),
                                packet.getOffset(), packet.getLength()));

                long magic = istream.readLong();

                // Only accepts CHAT-MAGIC-NUMBER of the Chat
                if (magic != CHAT_MAGIC_NUMBER) {
                    continue;

                }

                // Let's analyze the received payload and msg types in rceoved datagram
                int opCode = istream.readInt();
                switch (opCode) {
                    case JOIN:
                        processJoin(istream, packet.getAddress(), packet.getPort());
                        break;
                    case LEAVE:
                        processLeave(istream, packet.getAddress(), packet.getPort());
                        break;
                    case MESSAGE:
                        processMessage(istream, packet.getAddress(), packet.getPort());
                        break;
                    default:
                        error("error; Unknown type " + opCode + " sent from  "
                                + packet.getAddress() + ":" + packet.getPort());
                }

            } catch (InterruptedIOException e) {

                /**
                 * Handler for Interruptions ...
                 * WILL DO NOTHING ,,,
                 * Used for debugging / control if wanted ... to notify the loop interruption
                 */

            } catch (Throwable e) {
                e.printStackTrace(); // TODO REMOVE
                error("Processing error: " + e.getClass().getName() + ": "
                        + e.getMessage());
            }
        }

        try {
            msocket.close();
        } catch (Throwable e) {}
    }
}