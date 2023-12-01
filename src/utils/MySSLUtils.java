package utils;

import javax.net.ssl.*;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;

public abstract class MySSLUtils {
    // ===== Factories and Connections =====


    /**
     * Create a Server Socket Factory
     * @param keystorePath the keystore path
     * @param password keystore password
     * @return Server Socket factory
     */
    public static ServerSocketFactory createServerSocketFactory(String keystorePath, String password) {
        SSLServerSocketFactory ssf = null;
        try {
            // Set up key manager to do server authentication
            SSLContext ctx = configSocketFactory(keystorePath,password);
            System.setProperty("KEYSTORE_PATH", keystorePath);
            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (Exception e) {
            e.printStackTrace();
            return SSLServerSocketFactory.getDefault();
        }
    }
    /**
     * Create a Client Socket Factory
     * @param clientKeystorePath the client keystore path
     * @param password keystore password
     * @return Client Socket factory
     */
    public static SSLSocketFactory createClientSocketFactory(String clientKeystorePath, String password) {
        try {
            // set up key manager to do server authentication
            SSLContext ctx = configSocketFactory(clientKeystorePath,password);
            return ctx.getSocketFactory();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Config the SSLContext
     * @param keystorePath the keystore path
     * @param password the keystore password
     * @return the SSLContext
     */
    private static SSLContext configSocketFactory(String keystorePath, String password){
        SSLContext ctx;
        try{
            // Set up key manager to do server authenticatio

            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keystorePath), password.toCharArray());
            System.setProperty("KEYSTORE_PATH", keystorePath);

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password.toCharArray());

            // Create SLL Context (truststore is added through the java run command
            // thus there is no need to add it here)
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
        return ctx;
    }


    /**
     * Creates a Server Socket
      * @param portNumber the port
     * @param serverKeystorePath the keystore path
     * @param password the keystore password
     * @param doClientAuth flag do client auth
     * @return the server socket
     */
    public static ServerSocket createServerSocket(int portNumber, String serverKeystorePath, String password,
            boolean doClientAuth) {
        try {
            ServerSocketFactory ssf = MySSLUtils.createServerSocketFactory(serverKeystorePath, password);
            ServerSocket ss = ssf.createServerSocket(portNumber);

            ((SSLServerSocket) ss).setEnabledProtocols(new String[] { "TLSv1.2" });
            ((SSLServerSocket) ss).setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
            ((SSLServerSocket) ss).setNeedClientAuth(doClientAuth);

            return ss;
        } catch (IOException e) {
            System.out.println("Problem with sockets: unable to start ClassServer: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Start new connection to server
     * @param factory the socket factory
     * @param hostname the server hostname
     * @param portNumber the server port
     * @return the socket
     */
    public static SSLSocket startNewConnectionToServer(SSLSocketFactory factory, String hostname, int portNumber) {
        try {
            SSLSocket socket = (SSLSocket) factory.createSocket(hostname, portNumber);
            socket.startHandshake();
            return socket;
        } catch (Exception e) {
            System.out.println("Unable to start connection.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Close socket connection
     * @param socket the socket
     */
    public static void closeConnectionToServer(Socket socket) {
        try {
            socket.close();
        } catch (Exception e) {
            System.out.println("Unable to close connection.");
            e.printStackTrace();
        }
    }

    // ===== Data Methods =====

    /**
     * Build package from command and content
     * @param command the command
     * @param content the content
     * @return the package
     */
    public static byte[] buildPackage(Command command, byte[] content) {
        // { Command(int) | Length(int) | Content(byte[])}
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, command.ordinal());
        bb.putInt(Integer.BYTES, content.length);
        bb.put(2 * Integer.BYTES, content);

        return data;
    }

    /**
     * Build a response package
     * @param errorCode the error code
     * @param content the content
     * @return the response package
     */
    public static byte[] buildResponse(int errorCode, byte[] content) {
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, errorCode);
        bb.putInt(Integer.BYTES, content.length);
        bb.put(2 * Integer.BYTES, content);

        return data;
    }

    /**
     * Build error response
     * @return return error response package
     */
    public static byte[] buildErrorResponse() {
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, CommonValues.ERROR_CODE);
        bb.putInt(Integer.BYTES, 0);
        bb.put(2 * Integer.BYTES, new byte[0]);

        return data;
    }

    /**
     * Send content to socket
     * @param socket the socket
     * @param data the data to be sent
     */
    public static void sendData(Socket socket, byte[] data) {
        try {
            OutputStream out = socket.getOutputStream();
            out.write(data);
            out.flush();
        } catch (Exception e) {
            System.out.println("Could not send data.");
            e.printStackTrace();
        }
    }

    /**
     * Receive data in socket
     * @param socket the socket
     * @return the data received in the socket
     */
    public static byte[] receiveData(Socket socket) {
        try {
            InputStream inputStream = socket.getInputStream();
            byte[] buffer = new byte[CommonValues.DATA_SIZE];
            int bytesRead = inputStream.read(buffer, 0, buffer.length);
            //System.out.println("Bytes Read: " + bytesRead);
            return buffer;
        } catch (Exception e) {
            System.out.println("Error receiving data.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * Reads content type {Content.size + Content}
     * @param bb the bytebuffer
     * @param curIdx the start position of insertion
     * @return the content
     */
    public static byte[] getNextBytes(ByteBuffer bb, int curIdx) {
        int length = bb.getInt(curIdx);
        curIdx += Integer.BYTES;

        byte[] array = new byte[length];
        bb.get(curIdx, array);
        curIdx += array.length;

        return array;
    }

    /**
     * Insert bytes in Byte buffer
     * @param bb the byte buffer
     * @param array the content to be inserted
     * @param curIdx the start position to insert
     * @return the end position of the insert
     */
    public static int putBytes(ByteBuffer bb, byte[] array, int curIdx) {
        bb.put(curIdx, array);
        return curIdx + array.length;
    }

    /**
     * Inserts content type {Content.size + Content}
     * @param bb the bytebuffer
     * @param array the content to be inserted
     * @param curIdx the start position of insertion
     * @return the end position of the insert
     */
    public static int putLengthAndBytes(ByteBuffer bb, byte[] array, int curIdx) {
        bb.putInt(curIdx, array.length);
        curIdx += Integer.BYTES;

        bb.put(curIdx, array);
        curIdx += array.length;

        return curIdx;
    }

    // ===== Debug Methods =====
    /**
     * Appends logs to file
     * @param author the class or author of the log
     * @param message the log
     */
    public static void printToLogFile(String author, String message) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("./log.txt", true))) {
            // Write the line to the file
            writer.write(String.format("%s: %s.\n", author, message));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
