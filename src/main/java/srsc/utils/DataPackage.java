package srsc.utils;

import java.nio.ByteBuffer;

// Package to send
public record DataPackage(Command command, int length, byte[] content) {

    public static DataPackage parse(byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);

        Command command = Command.getCommandFromOrdinal(bb.getInt());
        int length = bb.getInt();

        byte[] content = new byte[length];
        bb.get(content);

        return new DataPackage(command, length, content);
    }
}
