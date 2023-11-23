package servers.AuthenticationServer;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

import utils.CommonValues;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

public class ASServer {

    private static final String SERVER_TRUSTSTORE_PATH = "../../certs/asCrypto/as_truststore";
    private static final String SERVER_KEYSTORE_PATH = "../../certs/asCrypto/keystore_as.jks";
    private static final String PASSWORD = "as123456";

    private static final boolean DO_CLIENT_AUTH = true;

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        ServerSocket ss = null;
        try {
            ServerSocketFactory ssf = getServerSocketFactory();
            ss = ssf.createServerSocket(CommonValues.AS_PORT_NUMBER);

            ((SSLServerSocket) ss).setEnabledProtocols(new String[] { "TLSv1.2" });
            ((SSLServerSocket) ss).setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
            ((SSLServerSocket) ss).setNeedClientAuth(DO_CLIENT_AUTH);
        } catch (IOException e) {
            System.out.println("Problem with sockets: unable to start ClassServer: " + e.getMessage());
            e.printStackTrace();
        }

        while (true) {
            Socket socket;
            try {
                System.out.println("Waiting for connection...");
                socket = ss.accept();
                System.out.println("Accepted a connection.");
            } catch (IOException e) {
                System.out.println("Server died: " + e.getMessage());
                e.printStackTrace();
                break;
            }

            new Thread() {
                @Override
                public void run() {
                    try {
                        byte[] dataIn = receiveData(socket);
                        DataPackage dp = DataPackage.parse(dataIn);

                        byte[] result = execute(dp);
                        sendData(socket, result);

                        socket.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }.start();
        }
        ss.close();
    }

    private static byte[] execute(DataPackage dp) {
        switch (dp.getCommand()) {
            case LOGIN:
                return AuthenticationServer.login(dp.getContent());
            default:
                return new byte[0];
        }
    }

    private static void sendData(Socket socket, byte[] data) {
        try {
            OutputStream out = socket.getOutputStream();
            out.write(data);
            out.flush();
        } catch (Exception e) {
            System.out.println("Could not send data.");
            e.printStackTrace();
        }
    }

    private static byte[] receiveData(Socket socket) {
        try {
            InputStream inputStream = socket.getInputStream();
            byte[] buffer = new byte[CommonValues.DATA_SIZE];
            int bytesRead = inputStream.read(buffer, 0, buffer.length);
            System.out.println("Bytes Read: " + bytesRead);
            return buffer;
        } catch (Exception e) {
            System.out.println("Error receiving data.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    private static ServerSocketFactory getServerSocketFactory() {
        SSLServerSocketFactory ssf = null;
        try {
            // set up key manager to do server authentication
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(SERVER_KEYSTORE_PATH), PASSWORD.toCharArray());

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, PASSWORD.toCharArray());

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

}