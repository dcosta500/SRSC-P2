package servers.MainDispatcher;

import utils.*;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class MainDispatcherServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/mdCrypto/md_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/mdCrypto/keystore_md.jks";
    private static final String PASSWORD = "md123456";

    private static final boolean DO_CLIENT_AUTH = true;

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.MD_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD,
                DO_CLIENT_AUTH);

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
            launchWorker(socket);
        }
        ss.close();
    }

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.getCommand()) {
            case SUM:
                return MainDispatcher.sum(dp.getContent());
            case MULT:
                return MainDispatcher.mult(dp.getContent());
            case LOGIN:
                return MainDispatcher.login(socket, dp.getContent());
            case STATS:
                return MainDispatcher.clientStats(socket, dp.getContent());
            case ACCESS:
                return MainDispatcher.access(socket, dp.getContent()) ;
            default:
                return new byte[0];
        }
    }

    private static void launchWorker(Socket socket) {
        new Thread() {
            @Override
            public void run() {
                try {
                    byte[] dataIn = MySSLUtils.receiveData(socket);
                    DataPackage dp = DataPackage.parse(dataIn);

                    byte[] result = executeCommand(socket, dp);
                    MySSLUtils.sendData(socket, result);

                    socket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }
}