package srsc.servers.Authentication;

import srsc.utils.MySQLiteUtils;
import srsc.utils.SQL;

public class AuthenticationUsersSQL extends SQL {

    public AuthenticationUsersSQL(String tableName, String dbFile) {
        super(tableName, dbFile);
        init();
    }

    private void init() {
        con = MySQLiteUtils.resetFile(DB_FILE_NAME);
        MySQLiteUtils.createTable(con, TABLE_NAME,
                "uid TEXT PRIMARY KEY, email TEXT, hPwd TEXT, salt TEXT, canBeAuthenticated BOOLEAN");
    }

    @Override
    public void insert(Object... args) {
        String values = createValuesString(args[0], args[1], args[2], args[3], args[4]);
        MySQLiteUtils.insert(con, TABLE_NAME, "uid, email, hPwd, salt, canBeAuthenticated", values);
    }

    @Override
    public void update(String condition, Object... args) {
        String values = createValuesString(args[0], args[1], args[2], args[3], args[4]);
        MySQLiteUtils.update(con, TABLE_NAME, values, condition);
    }

    @Override
    protected String createValuesString(Object... params) {
        return String.format("'%s', '%s', '%s', '%s', %d", params[0], params[1], params[2], params[3], ((boolean) params[4]) ? 1 : 0);
    }

}
