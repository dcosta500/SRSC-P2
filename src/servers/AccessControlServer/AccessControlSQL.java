package servers.AccessControlServer;

import utils.MySQLiteUtils;

import java.sql.Connection;
import java.sql.ResultSet;

public class AccessControlSQL {
    private static final String TABLE_NAME = "users";
    private static final String DB_FILE_NAME = "permissions.db";

    private Connection con;

    public AccessControlSQL() {
        init();
    }

    private void init() {
        con = MySQLiteUtils.resetFile(DB_FILE_NAME);
        MySQLiteUtils.createTable(con, TABLE_NAME,
                "uid TEXT PRIMARY KEY, serviceID TEXT PRIMARY KEY, permission TEXT");
    }

    public ResultSet select(String columns, String condition) {
        return MySQLiteUtils.select(con, TABLE_NAME, columns, condition);
    }

    public void insert(String uid, String serviceID, String permission) {
        String values = createValuesString(uid, serviceID,permission);
        MySQLiteUtils.insert(con, TABLE_NAME, "uid, serviceID, permission", values);
    }

    public void update(String uid, String serviceID, String permission, String condition) {
        String values = createValuesString(uid, serviceID,permission);
        MySQLiteUtils.update(con, TABLE_NAME, values, condition);
    }

    public void delete(String condition) {
        MySQLiteUtils.delete(con, TABLE_NAME, condition);
    }

    public void deleteAll() {
        MySQLiteUtils.deleteAll(con, TABLE_NAME);
    }

    private String createValuesString(String uid, String serviceId, String permission) {
        return String.format("'%s', '%s', '%s'", uid, serviceId, permission);
    }
}
