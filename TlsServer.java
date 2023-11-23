import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;

public class TlsServer {
    private static final boolean DO_CLIENT_AUTH = true;

    //private static final String SERVER_KEYSTORE_PATH = "certs/mdCrypto/selfsigned_md.jks";
    private static final String SERVER_KEYSTORE_PATH = "certs/mdCrypto/keystore_md.jks";
    private static final String PASSWORD = "md123456";

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.out.println("Please provide a port number.");
            return;
        }

        int portNumber = Integer.parseInt(args[0]);

        ServerSocket ss = null;
        try {
            ServerSocketFactory ssf = getServerSocketFactory();
            ss = ssf.createServerSocket(portNumber);

            // This server only enables TLSv1.2
            // and the cipher suite below
            ((SSLServerSocket) ss).setEnabledProtocols(new String[] { "TLSv1.2" });
            ((SSLServerSocket) ss).setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
            ((SSLServerSocket) ss).setNeedClientAuth(DO_CLIENT_AUTH);
        } catch (IOException e) {
            System.out.println("Problem with sockets: unable to start ClassServer: " + e.getMessage());
            e.printStackTrace();
        }

        Socket socket;
        try {
            System.out.println("Waiting for connection...");
            socket = ss.accept();
            System.out.println("Accepted a connection.");
        } catch (IOException e) {
            System.out.println("Class Server died: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Execute
        try {
            PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    socket.getOutputStream())));
            //DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            try {
                out.println("Hi!");
                out.flush();
            } catch (Exception e) {
                e.printStackTrace();
                // write out error response
                out.println("Error");
                out.flush();
            }

        } catch (IOException ex) {
            // eat exception (could log error to log file, but
            // write out to stdout for now).
            System.out.println("error writing response: " + ex.getMessage());
            ex.printStackTrace();

        } finally {
            try {
                System.out.println("Closing connection...");
                socket.close();
            } catch (IOException e) {
            }
        }
    }

    private static ServerSocketFactory getServerSocketFactory() {
        SSLServerSocketFactory ssf = null;
        try {
            // set up key manager to do server authentication
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;

            // Keystore
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(SERVER_KEYSTORE_PATH), PASSWORD.toCharArray());

            // Key Manager Factory
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, PASSWORD.toCharArray());

            // Create SLL Context (truststore is added through the java run command
            // thus there is no need to add it here)
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);

            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (Exception e) {
            e.printStackTrace();
            return SSLServerSocketFactory.getDefault();
        }
    }
}
