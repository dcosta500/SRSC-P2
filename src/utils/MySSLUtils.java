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
import java.nio.ByteBuffer;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;

public abstract class MySSLUtils {
    // ===== Factories and Connections =====
    public static ServerSocketFactory createServerSocketFactory(String keystorePath, String password) {
        SSLServerSocketFactory ssf = null;
        try {
            // Set up key manager to do server authentication
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keystorePath), password.toCharArray());

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password.toCharArray());

            // Create SLL Context (truststore is added through the java run command
            // thus there is no need to add it here)
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);

            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (Exception e) {
            e.printStackTrace();
            return SSLServerSocketFactory.getDefault();
        }
    }

    public static SSLSocketFactory createClientSocketFactory(String clientKeystorePath, String password) {
        try {
            // set up key manager to do server authentication
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(clientKeystorePath), password.toCharArray());

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password.toCharArray());

            // Create SLL Context (truststore is added through the java run command
            // thus there is no need to add it here)
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);

            return ctx.getSocketFactory();
        } catch (Exception e) {
            return null;
        }
    }

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

    public static void closeConnectionToServer(Socket socket) {
        try {
            socket.close();
        } catch (Exception e) {
            System.out.println("Unable to close connection.");
            e.printStackTrace();
        }
    }

    // ===== Data Methods =====
    public static byte[] buildPackage(Command command, byte[] content) {
        // { Command(int) | Length(int) | Content(byte[])}
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, command.ordinal());
        bb.putInt(Integer.BYTES, content.length);
        bb.put(2 * Integer.BYTES, content);

        return data;
    }

    public static byte[] buildResponse(int errorCode, byte[] content) {
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, errorCode);
        bb.putInt(Integer.BYTES, content.length);
        bb.put(2 * Integer.BYTES, content);

        return data;
    }

    public static byte[] buildErrorResponse() {
        byte[] data = new byte[CommonValues.DATA_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(0, CommonValues.ERROR_CODE);
        bb.putInt(Integer.BYTES, 0);
        bb.put(2 * Integer.BYTES, new byte[0]);

        return data;
    }

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

    // ===== Debug Methods =====
    public static void printToLogFile(String author, String message) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("./log.txt", true))) {
            // Write the line to the file
            writer.write(String.format("%s: %s.\n", author, message));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
