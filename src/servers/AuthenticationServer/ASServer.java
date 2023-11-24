package servers.AuthenticationServer;

import utils.*;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class ASServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/asCrypto/as_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/asCrypto/keystore_as.jks";
    private static final String PASSWORD = "as123456";

    private static final boolean DO_CLIENT_AUTH = true;

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.AS_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD,
                DO_CLIENT_AUTH);

        testSQLite();

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

    private static void testSQLite() {
        try {
            String curDir = System.getProperty("user.dir");

            Class.forName("org.sqlite.JDBC");
            String jdbcUrl = String.format("jdbc:sqlite:%s/%s", curDir, "db/mydb.db");
            Connection conn = DriverManager.getConnection(jdbcUrl);
            Statement statement = conn.createStatement();
            statement.execute("");
            statement.execute("INSERT INTO person (id,name,age) VALUES ('a', 'b', 18)");
            conn.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}