package client;

import javax.net.ssl.*;

import client.responseModels.AccessResponseModel;
import client.responseModels.LoginResponseModel;
import utils.*;

import java.security.Key;
import java.util.Scanner;

public class Client {
    private static final String CLIENT_BOOT_MESSAGE =
            "   _____  _  _               _   \n" +
            "  / ____|| |(_)             | |  \n" +
            " | |     | | _   ___  _ __  | |_ \n" +
            " | |     | || | / _ \\| '_ \\ | __|\n" +
            " | |____ | || ||  __/| | | || |_ \n" +
            "  \\_____||_||_| \\___||_| |_| \\__|\n" +
            "                                 \n" +
            "                                 ";
    private static String uid;

    private static SSLSocketFactory factory;
    private static SSLSocket socket;
    private static final String PASSWORD = "cl123456";

    private static byte[] auth_ktoken1024;
    private static Key client_ac_key;

    private static byte[] control_vtoken1024;

    private static Key client_ss_key;

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

        // TODO: Add exit and help instructions
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
                case STATS:
                    ClientCommands.stats(socket);
                    break;
                case LOGIN:
                    LoginResponseModel lrm = ClientCommands.login(socket, cmd);
                    processLoginResponse(lrm);
                    break;
                case ACCESS:
                    AccessResponseModel arm = ClientCommands.access(socket, auth_ktoken1024, client_ac_key, uid, cmd);
                    processAccessControlResponse(arm);
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
        client_ac_key = lrm.clientAc_SymKey;
    }

    private static void processAccessControlResponse(AccessResponseModel arm) {
        if (arm == null) {
            return;
        }

        control_vtoken1024 = arm.kvtoken1024;
        System.out.println("Access Control granted successfuly done at: " + arm.timestampFinal.toString());
        client_ss_key = arm.clientService_key;
    }

    public static void main(String[] args) throws Exception {
        //System.out.println(InetAddress.getLocalHost().getHostAddress());

        System.out.println(CLIENT_BOOT_MESSAGE);

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
