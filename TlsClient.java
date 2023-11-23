import javax.net.ssl.*;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

public class TlsClient {

    //private static final String CLIENT_KEYSTORE_PATH = "certs/clients/aliceCrypto/selfsigned_alice_cl.jks";
    private static final String CLIENT_KEYSTORE_PATH = "certs/clients/aliceCrypto/keystore_alice_cl.jks";
    private static final String PASSWORD = "cl123456";

    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            System.out.println("Provide a hostname and a port number.");
            return;
        }

        String hostname = args[0];
        int portNumber = Integer.parseInt(args[1]);

        try {
            SSLSocketFactory factory = null;
            try {
                // set up key manager to do server authentication
                SSLContext ctx;
                KeyManagerFactory kmf;
                KeyStore ks;

                // Keystore
                ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream(CLIENT_KEYSTORE_PATH), PASSWORD.toCharArray());

                // Key Manager Factory
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, PASSWORD.toCharArray());

                // Create SLL Context (truststore is added through the java run command
                // thus there is no need to add it here)
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), null, null);

                factory = ctx.getSocketFactory();
            } catch (Exception e) {
                throw new IOException(e.getMessage());
            }

            SSLSocket socket = (SSLSocket) factory.createSocket(hostname, portNumber);
            socket.startHandshake();

            PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    socket.getOutputStream())));
            out.println("Hello");
            out.flush();

            /*
             * Make sure there were no surprises
             */
            if (out.checkError())
                System.out.println(
                        "SSLSocketClient: java.io.PrintWriter error");

            /* read response */
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            socket.getInputStream()));

            String inputLine;

            while ((inputLine = in.readLine()) != null)
                System.out.println(inputLine);

            in.close();
            out.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
