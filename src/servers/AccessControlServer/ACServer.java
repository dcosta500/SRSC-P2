package servers.AccessControlServer;

import servers.AuthenticationServer.AuthUsersSQL;
import servers.AuthenticationServer.DataPackage;
import utils.CommonValues;
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

    private static final Set<Long> nonceSet = new HashSet<>();

    // TODO: Fazer a BD do Access Control
    // as entries dessa bd vao ter o formato indicado no enunciado
    // { uid, permissions }
    // permissions é uma string que pode ter 3 valores (as quais já têm constantes
    // criadas no CommonValues class):
    // "deny", "allow read", "allow read write"
    private static AuthUsersSQL users;

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        switch (dp.getCommand()) {
            case ACCESS:
                return AccessControlServer.access(socket, nonceSet, dp.getContent());
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

        // TODO: Não uses os .conf doutros servers aqui. Qualquer coisa copia mesmo
        // a informação de um .conf para o deste server.

        try (FileInputStream input = new FileInputStream(curDir + "/src/configs/auth_server.conf")) {
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

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        // TODO: Faz aqui um initDB() tal como no auth
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
