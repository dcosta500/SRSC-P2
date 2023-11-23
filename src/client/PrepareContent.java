package client;

import java.nio.ByteBuffer;

public class PrepareContent {
    // Build the content for each mainDispatcher operation

    public static byte[] prepareSumContent(int i) {
        byte[] content = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(content);

        bb.putInt(0, i);
        return content;
    }

    public static byte[] prepareMultContent(int i) {
        byte[] content = new byte[Integer.BYTES];
        ByteBuffer bb = ByteBuffer.wrap(content);

        bb.putInt(0, i);
        return content;
    }
}
