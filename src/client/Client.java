package client;

import javax.net.ssl.*;

import client.responseModels.LoginResponseModel;
import utils.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Scanner;

public class Client {

    private static String uid;

    private static SSLSocketFactory factory;
    private static SSLSocket socket;
    private static final String PASSWORD = "cl123456";

    private static byte[] auth_ktoken1024;
    private static Key client_auth_key;

    private static void readCommands() {
        /*
         * Instructions to add a new command
         * 1- Create command enum in Command.java
         * 2- Add Command enum to both switches (client and server)
         * 3- Create method in ClientCommands
         * 4- Create command in MainDispatcher class (not MainDispatcherServer class)
         * 
         * Format of packages to be sent:
         * { Command(int) | Length of Content(int) | Content(byte[]) }
         * 
         * Format of packages being received:
         * { Error Code(int) | Length of Content(int) | Content(byte[]) }
         */

        Scanner in = new Scanner(System.in);
        while (true) {
            socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.MD_HOSTNAME,
                    CommonValues.MD_PORT_NUMBER);
            System.out.print("Command -> ");
            String cmd = in.nextLine();
            switch (Command.valueOf(cmd.split(" ")[0].toUpperCase())) {
                case SUM:
                    ClientCommands.sum(socket);
                    break;
                case MULT:
                    ClientCommands.mult(socket);
                    break;
                case LOGIN:
                    LoginResponseModel lrm = ClientCommands.login(socket, cmd);
                    processLoginResponse(lrm);
                    break;
                case STATS:
                    ClientCommands.stats(socket);
                    break;
                default:
            }
            MySSLUtils.closeConnectionToServer(socket);
        }

    }

    private static void processLoginResponse(LoginResponseModel lrm) {
        if (lrm == null) {
            return;
        }

        auth_ktoken1024 = lrm.ktoken1024;
        System.out.println("Login successfuly done at: " + lrm.timestampFinal.toString());
        client_auth_key = lrm.clientAc_SymKey;
    }

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.out.println("Provide a client name.");
            return;
        }

        uid = args[0];

        String client_keystore_path = String.format("certs/clients/%sCrypto/keystore_%s_cl.jks", args[0], args[0]);
        System.setProperty("javax.net.ssl.trustStore",
                String.format("certs/clients/%sCrypto/%s_cl_truststore", args[0], args[0]));

        try {
            factory = MySSLUtils.createClientSocketFactory(client_keystore_path, PASSWORD);
            readCommands();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
