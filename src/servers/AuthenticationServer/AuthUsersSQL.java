package servers.AuthenticationServer;

import java.sql.Connection;
import java.sql.ResultSet;

import utils.MySQLiteUtils;

public class AuthUsersSQL {

    private static final String TABLE_NAME = "users";
    private static final String DB_FILE_NAME = "auth.db";

    private Connection con;

    public AuthUsersSQL() {
        init();
    }

    private void init() {
        con = MySQLiteUtils.resetFile(DB_FILE_NAME);
        MySQLiteUtils.createTable(con, TABLE_NAME,
                "uid TEXT PRIMARY KEY, email TEXT, hPwd TEXT, canBeAuthenticated BOOLEAN");
    }

    public ResultSet select(String columns, String condition) {
        return MySQLiteUtils.select(con, TABLE_NAME, columns, condition);
    }

    public void insert(String uid, String email, String hPwd, boolean canBeAuthenticated) {
        String values = createValuesString(uid, email, hPwd, canBeAuthenticated);
        MySQLiteUtils.insert(con, TABLE_NAME, "uid, email, hPwd, canBeAuthenticated", values);
    }

    public void update(String uid, String email, String hPwd, boolean canBeAuthenticated, String condition) {
        String values = createValuesString(uid, email, hPwd, canBeAuthenticated);
        MySQLiteUtils.update(con, TABLE_NAME, values, condition);
    }

    public void delete(String condition) {
        MySQLiteUtils.delete(con, TABLE_NAME, condition);
    }

    public void deleteAll() {
        MySQLiteUtils.deleteAll(con, TABLE_NAME);
    }

    private String createValuesString(String uid, String email, String hPwd, boolean canBeAuthenticated) {
        return String.format("'%s', '%s', '%s', %d", uid, email, hPwd, canBeAuthenticated ? 1 : 0);
    }

}
