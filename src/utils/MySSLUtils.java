package utils;

import javax.net.ssl.*;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.Properties;

import javax.net.ServerSocketFactory;

public abstract class MySSLUtils {


    // ===== Factories and Connections =====

    /**
     * Create a Server Socket Factory
     *
     * @param keystorePath the keystore path
     * @param password     keystore password
     * @return Server Socket factory
     */
    public static ServerSocketFactory createServerSocketFactory(String keystorePath, String password) {
        SSLServerSocketFactory ssf = null;
        try {
            // Set up key manager to do server authentication
            SSLContext ctx = configSocketFactory(keystorePath, password);
            System.setProperty("KEYSTORE_PATH", keystorePath);
            assert ctx != null;
            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (Exception e) {
            e.printStackTrace();
            return SSLServerSocketFactory.getDefault();
        }
    }

    /**
     * Create a Client Socket Factory
     *
     * @param clientKeystorePath the client keystore path
     * @param password           keystore password
     * @return Client Socket factory
     */
    public static SSLSocketFactory createClientSocketFactory(String clientKeystorePath, String password) {
        try {
            // set up key manager to do server authentication
            SSLContext ctx = configSocketFactory(clientKeystorePath, password);
            assert ctx != null;
            return ctx.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Config the SSLContext
     *
     * @param keystorePath the keystore path
     * @param password     the keystore password
     * @return the SSLContext
     */
    private static SSLContext configSocketFactory(String keystorePath, String password) {
        SSLContext ctx;
        try {
            // Set up key manager to do server authentication
            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keystorePath), password.toCharArray());
            System.setProperty("KEYSTORE_PATH", keystorePath);

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password.toCharArray());

            // Create SLL Context
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return ctx;
    }

    /**
     * Start new connection to server
     *
     * @param factory    the socket factory
     * @param hostname   the server hostname
     * @param portNumber the server port
     * @return the socket
     */
    public static SSLSocket startNewConnectionToServer(SSLSocketFactory factory, String hostname, int portNumber) {
        String curDir = System.getProperty("user.dir");

        Properties tlsProps = new Properties();
        try (FileInputStream input = new FileInputStream(curDir + "/configs/tlsConfig/client.conf")) {
            tlsProps.load(input);
        } catch (Exception e) {
            System.out.println("Could not load tls server configurations.");
            return null;
        }

        String[] tlsVersion = tlsProps.getProperty("TLS_PROT_ENF").split(",");
        boolean tlsAuth = tlsProps.getProperty("TLS_AUTH").equals("MUTUAL");
        String[] tlsCiphersuites = tlsProps.getProperty("CIPHERSUITES").split(",");

        try {
            SSLSocket socket = (SSLSocket) factory.createSocket(hostname, portNumber);

            socket.setEnabledProtocols(tlsVersion);
            socket.setNeedClientAuth(tlsAuth);
            socket.setEnabledCipherSuites(tlsCiphersuites);

            socket.setReceiveBufferSize(CommonValues.DATA_SIZE);
            socket.setSendBufferSize(CommonValues.DATA_SIZE);

            socket.startHandshake();
            return socket;
        } catch (Exception e) {
            System.out.println("Unable to start connection.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Creates a Server Socket.
     *
     * @param portNumber         the port
     * @param serverKeystorePath the keystore path
     * @param password           the keystore password
     * @return the server socket
     */
    public static ServerSocket createServerSocket(int portNumber, String serverKeystorePath, String password) {
        String curDir = System.getProperty("user.dir");

        Properties tlsProps = new Properties();
        try (FileInputStream input = new FileInputStream(curDir + "/configs/tlsConfig/server.conf")) {
            tlsProps.load(input);
        } catch (Exception e) {
            System.out.println("Could not load tls server configurations.");
            return null;
        }

        String[] tlsVersion = tlsProps.getProperty("TLS_PROT_ENF").split(",");
        boolean tlsAuth = tlsProps.getProperty("TLS_AUTH").equals("MUTUAL");
        String[] tlsCiphersuites = tlsProps.getProperty("CIPHERSUITES").split(",");

        try {
            ServerSocketFactory ssf = MySSLUtils.createServerSocketFactory(serverKeystorePath, password);
            ServerSocket ss = ssf.createServerSocket(portNumber);

            ((SSLServerSocket) ss).setEnabledProtocols(tlsVersion);
            ((SSLServerSocket) ss).setNeedClientAuth(tlsAuth);
            ((SSLServerSocket) ss).setEnabledCipherSuites(tlsCiphersuites);

            ss.setReceiveBufferSize(CommonValues.DATA_SIZE);

            return ss;
        } catch (IOException e) {
            System.out.println("Problem with sockets: unable to start server: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Close socket connection
     *
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
     *
     * @param command the command
     * @param content the content
     * @return the package
     */
    public static byte[] buildPackage(Command command, byte[] content) {
        // { Command(int) | Length(int) | Content(byte[])}
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(command.ordinal());
        MySSLUtils.putLengthAndBytes(bb, content);

        return data;
    }

    /**
     * Build a response package
     *
     * @param statusCode the status code
     * @param content   the content
     * @return the response package
     */
    public static byte[] buildResponse(int statusCode, byte[] content) {
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(statusCode);
        MySSLUtils.putLengthAndBytes(bb, content);

        return data;
    }

    /**
     * Build error response
     *
     * @return return error response package
     */
    public static byte[] buildErrorResponse() {
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(CommonValues.ERROR_CODE);
        MySSLUtils.putLengthAndBytes(bb, new byte[0]);

        return data;
    }

    /**
     * Send content to socket
     *
     * @param socket the socket
     * @param data   the data to be sent
     */
    public static void sendData(Socket socket, byte[] data) {
        try {
            OutputStream out = socket.getOutputStream();

            byte[] aux = null;
            if (data.length != CommonValues.DATA_SIZE) {
                aux = new byte[CommonValues.DATA_SIZE];
                System.arraycopy(data, 0, aux, 0, Math.min(data.length, aux.length));
            }

            out.write(aux == null ? data : aux);
            out.flush();
        } catch (Exception e) {
            System.out.println("Could not send data.");
            e.printStackTrace();
        }
    }

    /**
     * Receive data in socket
     *
     * @param socket the socket
     * @return the data received in the socket
     */
    public static byte[] receiveData(Socket socket) {
        try {
            InputStream inputStream = socket.getInputStream();
            byte[] buffer = new byte[CommonValues.DATA_SIZE];
            int bytesRead = inputStream.read(buffer, 0, buffer.length);
            if (bytesRead == 0) return new byte[0];
            return buffer;
        } catch (Exception e) {
            System.out.println("Error receiving data.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * Reads content type {Content.size + Content}
     *
     * @param bb the bytebuffer
     * @return the content
     */
    public static byte[] getNextBytes(ByteBuffer bb) {
        int length = bb.getInt();

        byte[] array = new byte[length];
        bb.get(array);

        return array;
    }

    /**
     * Insert bytes in Byte buffer
     *
     * @param bb    the byte buffer
     * @param array the content to be inserted
     */
    public static void putBytes(ByteBuffer bb, byte[] array) {
        bb.put(array);
    }

    /**
     * Inserts content type {Content.size + Content}
     *
     * @param bb    the bytebuffer
     * @param arrays the content to be inserted
     */
    public static void putLengthAndBytes(ByteBuffer bb, byte[]... arrays) {
        for (byte[] array : arrays) {
            bb.putInt(array.length);
            bb.put(array);
        }
    }

    // ===== Debug Methods =====

    /**
     * Appends logs to file
     *
     * @param author  the class or author of the log
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
