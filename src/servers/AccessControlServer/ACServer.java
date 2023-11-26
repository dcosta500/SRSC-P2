package servers.AccessControlServer;

import servers.AuthenticationServer.AuthUsersSQL;
import servers.AuthenticationServer.DataPackage;
import utils.CommonValues;
import utils.CryptoStuff;
import utils.MySSLUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class ACServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/acCrypto/ac_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/acCrypto/keystore_ac.jks";
    private static final String PASSWORD = "ac123456";
    private static final boolean DO_CLIENT_AUTH = true;

    private static final String[] usernames = { "alice", "bob", "carol", "david", "eric" };

    private static final Set<Long> nonceSet = new HashSet<>();


    private static AccessControlSQL users;

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.getCommand()) {
            case ACCESS:
                return AccessControlServer.access(socket, nonceSet, dp.getContent(),users);
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

    private static void initConf() {
        Properties props = new Properties();
        String curDir = System.getProperty("user.dir");



        try (FileInputStream input = new FileInputStream(curDir + "/src/configs/access_control_server.conf")) {
            props.load(input);
            System.setProperty("SYM_KEY_AUTH_AC", props.getProperty("SYM_KEY_AUTH_AC"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (FileInputStream input = new FileInputStream(curDir + "/src/configs/access_control_server.conf")) {
            props.load(input);
            System.setProperty("SYM_KEY_AC_SS", props.getProperty("SYM_KEY_AC_SS"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void initDb() {
        try {
            Class.forName("org.sqlite.JDBC");

            users = new AccessControlSQL();
            users.insert("alice",CommonValues.SS_ID,CommonValues.PERM_READ_WRITE);
            users.insert("bob",CommonValues.SS_ID,CommonValues.PERM_READ);
            users.insert("carol",CommonValues.SS_ID,CommonValues.PERM_DENY);
            users.insert("david",CommonValues.SS_ID,CommonValues.PERM_DENY);
            users.insert("eric",CommonValues.SS_ID,CommonValues.PERM_READ);
        } catch (Exception e) {
            System.out.println("Error while trying to initialize database.");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);


        initDb();
        initConf();

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.AC_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD,
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
}
