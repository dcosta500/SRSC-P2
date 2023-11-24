package client;

import javax.net.ssl.*;

import utils.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class TlsClient {
    private static SSLSocketFactory factory;
    private static SSLSocket socket;
    private static final String PASSWORD = "cl123456";

    private static void readCommands() {
        /*
         * Instructions to add a new command
         * 1- Create command enum in Command.java
         * 2- Add Command enum to both switches (client and server)
         * 3- Create execute{yourcommand}Command method here in this class
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
            switch (Command.valueOf(cmd.toUpperCase())) {
                case SUM:
                    executeSumCommand();
                    break;
                case MULT:
                    executeMultCommand();
                    break;
                case LOGIN:
                    executeLoginCommand();
                    break;
                case STATS:
                    executeStatsCommand();
                    break;
                default:
            }
            MySSLUtils.closeConnectionToServer(socket);
        }
    }

    private static void executeSumCommand() {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {int}

        // Output: { code(int) | length(int) | content(byte[])}

        // ===== Build Content Input =====
        byte[] inputContent = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.putInt(0, 5);

        // ===== Send Content =====
        byte[] dataOut = MySSLUtils.buildPackage(Command.SUM, inputContent);
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        int result = bb.getInt(0);
        System.out.println("Result: " + result);
    }

    private static void executeMultCommand() {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {int}

        // Output: { code(int) | length(int) | content(byte[])}

        // ===== Build Content Input =====
        byte[] inputContent = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(inputContent);

        bb.putInt(0, 5);

        // ===== Send Content =====
        byte[] dataOut = MySSLUtils.buildPackage(Command.MULT, inputContent);
        MySSLUtils.sendData(socket, dataOut);

        // ===== Receive Response =====
        byte[] dataIn = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(dataIn);

        // ===== Unpack Response =====
        if (rp.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb = ByteBuffer.wrap(rp.getContent());

        int result = bb.getInt(0);
        System.out.println("Result: " + result);
    }

    private static void executeLoginCommand() {
        // Input: { command(int) | length(int) | content(byte[]) }
        // content: {string}

        // Output: { code(int) | length(int) | content(byte[])}
        // content: {string_ac}

        // ===== Build Content Input =====
        byte[] message1 = "hello".getBytes();

        byte[] inputContent1 = new byte[message1.length];
        ByteBuffer bb1 = ByteBuffer.wrap(inputContent1);

        bb1.put(0, message1);

        // ===== Send Content =====
        byte[] dataOut1 = MySSLUtils.buildPackage(Command.LOGIN, inputContent1);
        MySSLUtils.sendData(socket, dataOut1);

        // ===== Receive Response =====
        byte[] dataIn1 = MySSLUtils.receiveData(socket);
        ResponsePackage rp1 = ResponsePackage.parse(dataIn1);

        // ===== Unpack Response =====
        if (rp1.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb1 = ByteBuffer.wrap(rp1.getContent());

        byte[] response1 = new byte[rp1.getLength()];
        bb1.get(0, response1);
        String response1String = new String(response1, StandardCharsets.UTF_8);

        System.out.println("Response 1: " + response1String);

        // ===== Second Round =====
        // ===== Build Content Input =====
        byte[] message2 = response1String.getBytes();

        byte[] inputContent2 = new byte[message2.length];
        ByteBuffer bb2 = ByteBuffer.wrap(inputContent2);

        bb2.put(0, message2);

        // ===== Send Content =====
        byte[] dataOut2 = MySSLUtils.buildPackage(Command.LOGIN, inputContent2);
        MySSLUtils.sendData(socket, dataOut2);

        // ===== Receive Response =====
        byte[] dataIn2 = MySSLUtils.receiveData(socket);
        ResponsePackage rp2 = ResponsePackage.parse(dataIn2);

        // ===== Unpack Response =====
        if (rp2.getCode() == CommonValues.ERROR_CODE) {
            System.out.println("Error code received. Aborting...");
            return;
        }

        bb2 = ByteBuffer.wrap(rp2.getContent());

        byte[] response2 = new byte[rp2.getLength()];
        bb2.get(0, response2);

        System.out.println("Response 2: " + new String(response2, StandardCharsets.UTF_8));
    }

    private static void executeStatsCommand() {
        byte[] dataToSend = MySSLUtils.buildPackage(Command.STATS, new byte[0]);
        MySSLUtils.sendData(socket, dataToSend);

        byte[] received = MySSLUtils.receiveData(socket);
        ResponsePackage rp = ResponsePackage.parse(received);
        ByteBuffer bb = ByteBuffer.wrap(rp.getContent());

        int length = bb.getInt(0);
        System.out.println("Length: " + length);

        byte[] ipAddBytes = new byte[length];
        bb.get(Integer.BYTES, ipAddBytes);

        System.out.println("Ip: " + new String(ipAddBytes, StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.out.println("Provide a client name.");
            return;
        }

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
