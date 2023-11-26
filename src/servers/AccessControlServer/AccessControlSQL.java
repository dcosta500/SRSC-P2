package servers.AccessControlServer;

import utils.MySQLiteUtils;
import utils.SQL;



public class AccessControlSQL extends SQL {




    public AccessControlSQL(String tableName, String dbFile) {
        super(tableName,dbFile);
        init();
    }

    private void init() {
        con = MySQLiteUtils.resetFile(DB_FILE_NAME);
        MySQLiteUtils.createTable(con, TABLE_NAME,
                "uid TEXT PRIMARY KEY, serviceID TEXT PRIMARY KEY, permission TEXT");
    }

    @Override
    public void insert(Object... args) {
        String values = createValuesString(args[0], args[1], args[2]);
        MySQLiteUtils.insert(con, TABLE_NAME, "uid, serviceID, permission", values);
    }

    @Override
    public void update(String condition, Object... args) {
        String values = createValuesString(args[0], args[1], args[2]);
        MySQLiteUtils.update(con, TABLE_NAME, values, condition);
    }



    @Override
    protected String createValuesString(Object... args) {
        return String.format("'%s', '%s', '%s'", args[0], args[1], args[2]);
    }
}
