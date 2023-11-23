package client;

import java.nio.ByteBuffer;

public class ResponsePackage {

    private final int code;
    private final int length;
    private final byte[] content;

    public ResponsePackage(int code, int length, byte[] content) {
        this.code = code;
        this.length = length;
        this.content = content;
    }

    public int getCode() {
        return this.code;
    }

    public int getLength() {
        return this.length;
    }

    public byte[] getContent() {
        return this.content;
    }

    public static ResponsePackage parse(byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);

        int code = bb.getInt(0);
        int length = bb.getInt(Integer.BYTES);

        byte[] content = new byte[length];
        bb.get(2 * Integer.BYTES, content);

        return new ResponsePackage(code, length, content);
    }
}
