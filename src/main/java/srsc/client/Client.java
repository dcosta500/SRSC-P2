package srsc.client;

import srsc.client.responseModels.*;
import srsc.utils.*;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client {

    private static String uid;
    private static String USERNAME_LOGGED = "";
    private static final String PASSWORD = "cl123456";

    private static SSLSocketFactory factory;
    private static SSLSocket socket;

    private static  final Map<String, byte[]> SALT_MAP = new HashMap<>(Map.ofEntries(
            Map.entry("alice", new byte[]{(byte) 14, (byte) 7, (byte) 212, (byte) 157, (byte) 18, (byte) 147, (byte) 221, (byte) 49}),
            Map.entry("bob", new byte[]{(byte) 15, (byte) 8, (byte) 213, (byte) 158, (byte) 19, (byte) 148, (byte) 222, (byte) 50}),
            Map.entry("carol", new byte[]{(byte) 16, (byte) 9, (byte) 214, (byte) 159, (byte) 20, (byte) 149, (byte) 223, (byte) 51}),
            Map.entry("david", new byte[]{(byte) 17, (byte) 10, (byte) 215, (byte) 160, (byte) 21, (byte) 150, (byte) 224, (byte) 52}),
            Map.entry("eric", new byte[]{(byte) 18, (byte) 11, (byte) 216, (byte) 161, (byte) 22, (byte) 151, (byte) 225, (byte) 53})
    ));

    private static void readCommands() {
        // TODO: Add help instruction. Add support for unknown instruction
        Scanner in = new Scanner(System.in);

        masterLoop:
        while (true) {
            System.out.print(USERNAME_LOGGED + "Command -> ");
            String cmd = in.nextLine();
            switch (processCommandAndOpenSocket(cmd)) {
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
                    break masterLoop;
                case HELP:
                    System.out.println(ClientMessages.HELP_MESSAGE);
                    break;
                default:
                    System.out.println("Unknown command. Type \"help\" for a list of available commands.\n");
                    continue masterLoop;
            }
            afterConnectionRoutine();
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

        LoginResponseModel lrm = ClientCommands.login(socket, cmd, SALT_MAP.get(uid));
        processLoginResponse(lrm);
    }

    private static void processLoginResponse(LoginResponseModel lrm) {
        if (lrm == null) {
            // If client had logged in successfully before
            if (ClientTokens.lrm != null)
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

    private static void copy(String cmd) {
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

    private static void remove(String cmd) {
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

    private static void file(String cmd) {
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

        if (cmd.split(" ").length == 2) { // list home root
            cmd += " /";
        }

        CommandResponseModel crm = ClientCommands.list(socket, ClientTokens.lrm.ktoken1024, ClientTokens.lrm.clientAc_SymKey,
                uid, cmd);
        processResponse(crm, "Could not list directory.");
    }

    private static void processResponse(CommandResponseModel crm, String errorMessage) {
        if (crm == null) {
            System.out.println(errorMessage);
            return;
        }

        System.out.println(crm.getResponse());
    }

    // ===== AUX METHODS =====
    private static Command processCommandAndOpenSocket(String cmd) {
        try {
            Command command = Command.getCommandFromValue(cmd.trim().split(" ")[0].toLowerCase());

            // Only opens the connection for a command that needs it
            if (command.needsConnection()) {
                socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.MD_HOSTNAME,
                        CommonValues.MD_PORT_NUMBER);
                if(socket == null)
                    throw new Exception();
            }

            return command;
        } catch (NullPointerException | IllegalArgumentException e) {
            return Command.UNKNOWN;
        } catch (Exception e) {
            // Something unexpected happened
            return Command.EXIT;
        }
    }

    private static void afterConnectionRoutine() {
        if (socket != null) {
            MySSLUtils.closeConnectionToServer(socket);
            socket = null;
        }
        System.out.println();
    }

    public static void main(String[] args) {
        System.out.println(ClientMessages.CLIENT_BOOT_MESSAGE);

        if (args.length < 1) {
            System.out.println("Provide a client name.");
            return;
        }

        // catch arguments
        uid = args[0];

        // paths
        String client_keystore_path = String.format("certs/clients/%sCrypto/keystore_%s_cl.jks", uid, uid);
        String client_truststore_path = String.format("certs/clients/%sCrypto/%s_cl_truststore", uid, uid);

        // envs
        System.setProperty("javax.net.ssl.trustStore", client_truststore_path);

        try {
            factory = MySSLUtils.createClientSocketFactory(client_keystore_path, PASSWORD);
            readCommands();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
