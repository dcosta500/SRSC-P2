package servers.MainDispatcher;

import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import utils.MySSLUtils;
import utils.ResponsePackage;
import utils.Command;
import utils.CommonValues;

public class MainDispatcher {

    public static byte[] mult(byte[] content) {
        ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {int}
        // Output -> content: {result_code(int) | length(int) | result(int)}

        // Unpack
        int i = input.getInt(0);

        // Start Method
        int result = i * 2;

        // Packing
        byte[] resultArray = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output = ByteBuffer.wrap(resultArray);

        // Result code
        output.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output.putInt(Integer.BYTES, Integer.BYTES);

        // Result
        output.putInt(2 * Integer.BYTES, result);

        return resultArray;
    }

    public static byte[] sum(byte[] content) {
        ByteBuffer input = ByteBuffer.wrap(content);
        // Input -> content: {int}
        // Output -> content: {int}

        // Unpack
        int i = input.getInt(0);

        // Start Method
        int result = i + 1;

        byte[] resultArray = new byte[CommonValues.DATA_SIZE];
        ByteBuffer output = ByteBuffer.wrap(resultArray);

        // Result code 
        output.putInt(0, CommonValues.OK_CODE);

        // Length of result
        output.putInt(Integer.BYTES, Integer.BYTES);

        // Result
        output.putInt(2 * Integer.BYTES, result);

        return resultArray;
    }

    public static byte[] clientStats(Socket clientSocket, byte[] content) {
        try {
            byte[] contentToSend = new byte[100];
            byte[] sBytes = clientSocket.getInetAddress().getHostAddress().getBytes();

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

        // ===== Receive 1 =====
        // ...

        // ===== Send 1 =====
        byte[] ipClientBytes_S1 = getClientIPAddress(clientSocket).getBytes();

        byte[] dataToSend_S1 = new byte[Integer.BYTES + ipClientBytes_S1.length + content.length];
        ByteBuffer bb = ByteBuffer.wrap(dataToSend_S1);

        int curIdx = 0;

        curIdx = MySSLUtils.putLengthAndBytes(bb, ipClientBytes_S1, curIdx);
        curIdx = MySSLUtils.putBytes(bb, content, curIdx);

        MySSLUtils.sendData(asSocket, dataToSend_S1);

        // ===== Receive 2 =====
        content = MySSLUtils.receiveData(asSocket);

        // ===== Send 2 =====
        MySSLUtils.sendData(clientSocket, content);

        // ===== Receive 3 =====
        content = MySSLUtils.receiveData(clientSocket);

        // ===== Send 3 =====
        byte[] dataToSend_S2 = new byte[Integer.BYTES + ipClientBytes_S1.length + content.length];
        bb = ByteBuffer.wrap(dataToSend_S2);

        curIdx = 0;

        curIdx = MySSLUtils.putLengthAndBytes(bb, ipClientBytes_S1, curIdx);
        curIdx = MySSLUtils.putBytes(bb, content, curIdx);

        MySSLUtils.sendData(asSocket, dataToSend_S2);

        // ===== Receive 4 =====
        content = MySSLUtils.receiveData(asSocket);
        ResponsePackage rp = ResponsePackage.parse(content);

        if (rp.getCode() == CommonValues.ERROR_CODE)
            return MySSLUtils.buildErrorResponse();

        // Close connection to AS
        MySSLUtils.closeConnectionToServer(asSocket);

        // ===== Send 4 =====
        return rp.getContent();
    }

    // ===== Aux Methods =====
    private static String getClientIPAddress(Socket cliSocket) {
        return cliSocket.getInetAddress().getHostAddress();
    }

    private static SSLSocket startConnectionToASServer() {
        SSLSocketFactory factory = MySSLUtils.createClientSocketFactory("certs/mdCrypto/keystore_md.jks", "md123456");
        SSLSocket socket = MySSLUtils.startNewConnectionToServer(factory, CommonValues.AS_HOSTNAME,
                CommonValues.AS_PORT_NUMBER);

        return socket;
    }
}
