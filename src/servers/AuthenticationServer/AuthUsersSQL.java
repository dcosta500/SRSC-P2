package servers.AuthenticationServer;

import java.sql.Connection;
import java.sql.ResultSet;

import utils.MySQLiteUtils;
import utils.SQL;

public class AuthUsersSQL extends SQL {


    public AuthUsersSQL(String tableName, String dbFile) {
        super(tableName,dbFile);
        init();
    }


    private void init() {
        con = MySQLiteUtils.resetFile(DB_FILE_NAME);
        MySQLiteUtils.createTable(con, TABLE_NAME,
                "uid TEXT PRIMARY KEY, email TEXT, hPwd TEXT, canBeAuthenticated BOOLEAN");
    }

    @Override
    public void insert(Object... args) {
        String values = createValuesString(args[0],args[1], args[2], args[3]);
        MySQLiteUtils.insert(con, TABLE_NAME, "uid, email, hPwd, canBeAuthenticated", values);
    }

    @Override
    public void update(String condition,Object... args) {
        String values = createValuesString(args[0],args[1], args[2], args[3]);
        MySQLiteUtils.update(con, TABLE_NAME, values, condition);
    }

    @Override
    protected String createValuesString(Object... params) {
        return String.format("'%s', '%s', '%s', %d", params[0], params[1], params[2], (boolean)params[3] ? 1 : 0);
    }

}
