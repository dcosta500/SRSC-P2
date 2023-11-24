package servers.AuthenticationServer;

import utils.*;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ASServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/asCrypto/as_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/asCrypto/keystore_as.jks";
    private static final String PASSWORD = "as123456";

    private static final boolean DO_CLIENT_AUTH = true;

    private static AuthUsersSQL users;

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        initDb();

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.AS_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD,
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
            case LOGIN:
                return AuthenticationServer.login(socket, dp.getContent());
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

    private static void initDb() {
        try {
            Class.forName("org.sqlite.JDBC");

            users = new AuthUsersSQL();
            users.insert("alice", "alice@mail.com", "password", true);

        } catch (Exception e) {
            System.out.println("Error while trying to initialize database.");
            e.printStackTrace();
        }
    }
}