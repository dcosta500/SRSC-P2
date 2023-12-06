package client;

import javax.net.ssl.*;

import client.responseModels.*;
import utils.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
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
    private static String USERNAME_LOGGED = "";
    private static final String PASSWORD = "cl123456";

    private static void readCommands() {
        /* *
         * Instructions to add a new command
         * 1- Create command enum in Command.java
         * 2- Add Command enum to both switches (client and server)
         * 3- Create method in ClientCommands
         * 4- Create command in MainDispatcher class (not MainDispatcherServer class)
         * 5- Create command in respective server
         * 6- Create in this class a method and the postProcessing for that command
         */

        // TODO: Add exit and help instructions. Add support for unknown instruction
        Scanner in = new Scanner(System.in);

        masterLoop:
        while (true) {
            // TODO: Maybe we should only open the socket if the command exists.
            socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.MD_HOSTNAME,
                    CommonValues.MD_PORT_NUMBER);

            System.out.print(USERNAME_LOGGED + "Command -> ");
            String cmd = in.nextLine();
            Command command = null;
            try{
                command = Command.valueOf(cmd.split(" ")[0].toUpperCase());
            } catch (Exception e){
                command = Command.EXIT;
            }
            switch (command) {
                case LOGIN:
                    login(cmd);
                    break;
                case MKDIR:
                    makedir(cmd);
                    break;
                case PUT:
                    put(cmd);
                    break;
                case GET:
                    get(cmd);
                    break;
                case LIST:
                    list(cmd);
                    break;
                case COPY:
                    copy(cmd);
                    break;
                case FILE:
                    file(cmd);
                    break;
                case REMOVE:
                    remove(cmd);
                    break;
                case EXIT:
                    System.out.println("Exiting...");
                default:
                    break masterLoop;
            }
            MySSLUtils.closeConnectionToServer(socket);
            System.out.println();
        }

    }

    // ===== COMMAND PROCESSING =====
    private static void login(String cmd) {
        if (!ClientValidator.loginValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        String name = cmd.split(" ")[1];
        if (!name.equals(uid)) {
            System.out.printf("This is not %s's computer.\n", name);
            return;
        }

        LoginResponseModel lrm = ClientCommands.login(socket, cmd);
        processLoginResponse(lrm);
    }

    private static void processLoginResponse(LoginResponseModel lrm) {
        if (lrm == null) {
            // If client had logged in successfully before
            if(ClientTokens.lrm != null)
                System.out.println("Authentication revoked. You will need to correctly login again.");

            ClientTokens.lrm = null;
            USERNAME_LOGGED = "";
            return;
        }

        ClientTokens.lrm = lrm;
        USERNAME_LOGGED = lrm.username + ":";
        System.out.println("Login successfully done at: " + ClientTokens.lrm.timestampFinal.toString());
    }

    private static void makedir(String cmd) {
        if (!ClientValidator.makedirValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        CommandResponseModel crm = ClientCommands.mkdir(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey, uid, cmd);
        processResponse(crm, "Could not create directory.");
    }

    private static void copy(String cmd){
        if (!ClientValidator.copyValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        CommandResponseModel crm = ClientCommands.copy(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not copy file.");
    }

    private static void remove(String cmd){
        if (!ClientValidator.putValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        CommandResponseModel crm = ClientCommands.remove(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not remove file.");
    }

    private static void file(String cmd){
        if (!ClientValidator.fileValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        CommandResponseModel crm = ClientCommands.file(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not retrieve file metadata.");
    }

    private static void put(String cmd) {
        if (!ClientValidator.putValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        CommandResponseModel crm = ClientCommands.put(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not create file.");
    }

    private static void get(String cmd) {
        if (!ClientValidator.putValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        CommandResponseModel crm = ClientCommands.get(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not download file.");
    }

    private static void list(String cmd) {
        if (!ClientValidator.listValidator(cmd)) {
            System.out.println("Command is not correctly formatted");
            return;
        }

        if (ClientTokens.lrm.ktoken1024 == null) {
            System.out.println("You haven't logged in yet.");
            return;
        }

        if(cmd.split(" ").length == 2){ // list home root
            cmd += " /";
        }

        CommandResponseModel crm = ClientCommands.list(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not list directory.");
    }

    private static void processResponse(CommandResponseModel crm, String errorMessage){
        if(crm == null){
            System.out.println(errorMessage);
            return;
        }

        System.out.println(crm.getResponse());
    }

    public static void main(String[] args) {
        System.out.println(CLIENT_BOOT_MESSAGE);

        if (args.length < 1) {
            System.out.println("Provide a client name.");
            return;
        }

        uid = args[0];

        // paths
        String client_keystore_path = String.format("certs/clients/%sCrypto/keystore_%s_cl.jks", uid, uid);
        String client_truststore_path = String.format("certs/clients/%sCrypto/%s_cl_truststore", uid, uid);

        // envs
        System.setProperty("javax.net.ssl.trustStore", client_truststore_path);

        try {
            factory = MySSLUtils.createClientSocketFactory(client_keystore_path, PASSWORD);
            readCommands();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
