package srsc.servers.MainDispatcher;

import srsc.utils.*;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;


public class MainDispatcherServer {

    private static final String SERVER_TRUSTSTORE_PATH = "certs/mdCrypto/md_truststore";
    private static final String SERVER_KEYSTORE_PATH = "certs/mdCrypto/keystore_md.jks";
    private static final String PASSWORD = "md123456";

    private static byte[] executeCommand(Socket socket, DataPackage dp) {
        System.out.println("Executing command...");
        switch (dp.command()) {
            case LOGIN:
                return MainDispatcherCommands.login(socket, dp.content());
            case ACCESS:
                return MainDispatcherCommands.access(socket, dp.content());
            case MKDIR:
                return MainDispatcherCommands.makedir(socket,dp.content());
            case PUT:
                return MainDispatcherCommands.put(socket,dp.content());
            case GET:
                return MainDispatcherCommands.get(socket,dp.content());
            case LIST:
                return MainDispatcherCommands.list(socket,dp.content());
            case FILE:
                return MainDispatcherCommands.file(socket,dp.content());
            case COPY:
                return MainDispatcherCommands.copy(socket,dp.content());
            case REMOVE:
                return MainDispatcherCommands.remove(socket,dp.content());
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

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE_PATH);

        ServerSocket ss = MySSLUtils.createServerSocket(CommonValues.MD_PORT_NUMBER, SERVER_KEYSTORE_PATH, PASSWORD);

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