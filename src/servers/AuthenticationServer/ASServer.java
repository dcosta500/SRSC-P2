package servers.AuthenticationServer;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

import utils.CommonValues;
import utils.MySSLUtils;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ASServer {

    private static final String SERVER_TRUSTSTORE_PATH = "../../certs/asCrypto/as_truststore";
    private static final String SERVER_KEYSTORE_PATH = "../../certs/asCrypto/keystore_as.jks";
    private static final String PASSWORD = "as123456";

    private static final boolean DO_CLIENT_AUTH = true;

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        ServerSocket ss = null;
        try {
            ServerSocketFactory ssf = MySSLUtils.createServerSocketFactory(SERVER_KEYSTORE_PATH, PASSWORD);
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
                        byte[] dataIn = MySSLUtils.receiveData(socket);
                        DataPackage dp = DataPackage.parse(dataIn);

                        byte[] result = execute(dp);
                        MySSLUtils.sendData(socket, result);

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
}