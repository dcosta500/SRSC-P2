package servers.MainDispatcher;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Base64;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import utils.MySSLUtils;
import utils.Command;
import utils.CommonValues;

public class MainDispatcher {

    public static byte[] clientStats(Socket clientSocket, byte[] content) {
        try {
            byte[] contentToSend = new byte[100];
            byte[] sBytes = getClientIPAddress(clientSocket).getBytes();

            ByteBuffer bb = ByteBuffer.wrap(contentToSend);
            bb.putInt(0, sBytes.length);
            bb.put(Integer.BYTES, sBytes);

            return MySSLUtils.buildResponse(CommonValues.OK_CODE, contentToSend);
        } catch (Exception e) {
            MySSLUtils.printToLogFile("Main Dispatcher", "Error in clientStats method.");
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static byte[] login(Socket clientSocket, byte[] content) {
        /**
        * Data flow (basically add client ip before redirecting to auth server):
        * Receive-1 -> {len + uid}
        * Send-1 -> {len+ipClient || len+uid}
        * Receive-2 -> dont care
        * Send-2 -> redirect receive-2
        * Receive-3 -> { len+Yclient || len+{ Secure Random }Kpwd }
        * Send-3 -> { len+IPclient || len+Yclient || len+{ Secure Random }Kpwd }
        * Receive-4 -> dont care
        * Send-4 -> redirect receive-4
        */
        SSLSocket asSocket = startConnectionToASServer();

        // ===== Receive 1 from client =====
        // ...

        // ===== Send 1 to as =====
        byte[] dataToSend_S1 = addClientIPToBeggining(clientSocket, content);

        MySSLUtils.sendData(asSocket, MySSLUtils.buildPackage(Command.LOGIN, dataToSend_S1));

        // ===== Receive 2 from as =====
        content = MySSLUtils.receiveData(asSocket);

        // ===== Send 2 to client =====
        MySSLUtils.sendData(clientSocket, content);

        // ===== Receive 3 from client =====
        content = MySSLUtils.receiveData(clientSocket);

        // ===== Send 3 to as =====
        byte[] dataToSend_S3 = addClientIPToBeggining(clientSocket, content);

        MySSLUtils.sendData(asSocket, dataToSend_S3);

        // ===== Receive 4 from as =====
        content = MySSLUtils.receiveData(asSocket);

        // Close connection to AS
        MySSLUtils.closeConnectionToServer(asSocket);

        // ===== Send 4 to client =====
        return content;
    }

    public static byte[] access(Socket clientSocket, byte[] content) {
        /*
         * Data flow (basically add client ip before redirecting to auth server):
         * Receive-1: { len+IdService || len+token1024 || len+AuthClient}
         * Send-1: { len+IPclient || len+IdService || len+token1024 || len+AuthClient}
         * Receive-2: dont care
         * Send-2: redirect
         */

        // ===== Receive-1 from client =====
        // ...

        // ===== Send-1 to ac =====
        SSLSocket acSocket = startConnectionToACServer();
        byte[] dataToSend_S1 = addClientIPToBeggining(clientSocket, content);
        MySSLUtils.sendData(acSocket, MySSLUtils.buildPackage(Command.ACCESS, dataToSend_S1));

        // ===== Receive-2 from ac =====
        content = MySSLUtils.receiveData(acSocket);

        // ===== Send-2 to client =====
        MySSLUtils.closeConnectionToServer(acSocket);
        return content;
    }

    public static byte[] makedir(Socket clientSocket, byte[] content){
        return executeReadCommand(clientSocket,content,Command.MKDIR);
    }
    public static byte[] put(Socket clientSocket, byte[] content){
        System.out.println("Executing put");
        return executeWriteCommand(clientSocket,content,Command.PUT);
    }

    // ===== Aux Methods =====
    private static byte[] executeReadCommand(Socket clientSocket, byte[] content, Command command){
        //===== Send 1 from ss =====
        byte[] dataToSend_S2 = addClientIPToBeggining(clientSocket, content);
        SSLSocket ssSocket = startConnectiontoSSServer();
        MySSLUtils.sendData(ssSocket, MySSLUtils.buildPackage(command, dataToSend_S2));

        //===== Receive 2 from ss =====
        content = MySSLUtils.receiveData(ssSocket);

        // ===== Send 2 to client =====
        MySSLUtils.sendData(clientSocket, content);

        //===== Receive 3 from client =====
        content = MySSLUtils.receiveData(clientSocket);

        // ===== Send 3 to SS =====
        byte[] dataToSend_S3 = addClientIPToBeggining(clientSocket, content);
        MySSLUtils.sendData(ssSocket, dataToSend_S3);

        //===== Receive 4 from SS ====

        content = MySSLUtils.receiveData(ssSocket);

        // ===== Send 4 to client =====
        return content;
    }

    private static byte[] executeWriteCommand(Socket clientSocket, byte[] content, Command command){
        //===== Send 1 to ss =====
        byte[] dataToSend_S2 = addClientIPToBeggining(clientSocket, content);
        SSLSocket ssSocket = startConnectiontoSSServer();
        MySSLUtils.sendData(ssSocket, MySSLUtils.buildPackage(command, dataToSend_S2));

        //===== Receive 2 from ss =====
        content = MySSLUtils.receiveData(ssSocket);

        // ===== Send 2 to client =====
        MySSLUtils.sendData(clientSocket, content);

        //===== Receive 3 from client =====
        content = MySSLUtils.receiveData(clientSocket);

        // ===== Client file =====
        byte[] fileBytes = MySSLUtils.receiveFile(clientSocket);

        // ===== Send 3 to SS =====
        byte[] dataToSend_S3 = addClientIPToBeggining(clientSocket, content);
        MySSLUtils.sendData(ssSocket, dataToSend_S3);

        // ==== SS Send file ====
        MySSLUtils.sendFile(ssSocket, fileBytes);

        //===== Receive 4 from SS ====
        content = MySSLUtils.receiveData(ssSocket);

        // ===== Send 4 to client =====
        return content;
    }

    private static byte[] addClientIPToBeggining(Socket clientSocket, byte[] content) {
        byte[] ipClientBytes = getClientIPAddress(clientSocket).getBytes();
        byte[] data = new byte[Integer.BYTES + ipClientBytes.length + content.length];
        ByteBuffer bb = ByteBuffer.wrap(data);

        MySSLUtils.putLengthAndBytes(bb, ipClientBytes);
        MySSLUtils.putBytes(bb, content);

        return data;
    }

    private static String getClientIPAddress(Socket cliSocket) {
        System.out.println("1:" + cliSocket.getInetAddress().toString());
        return cliSocket.getInetAddress().getHostAddress();
    }

    private static SSLSocket startConnectionToASServer() {
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory("certs/mdCrypto/keystore_md.jks", "md123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.AS_HOSTNAME,
                CommonValues.AS_PORT_NUMBER);

        return socket;
    }

    private static SSLSocket startConnectionToACServer() {
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory("certs/mdCrypto/keystore_md.jks", "md123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.AC_HOSTNAME,
                CommonValues.AC_PORT_NUMBER);

        return socket;
    }

    private static SSLSocket startConnectiontoSSServer(){
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory("certs/mdCrypto/keystore_md.jks", "md123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.SS_HOSTNAME,
                CommonValues.SS_PORT_NUMBER);

        return socket;
    }
}
