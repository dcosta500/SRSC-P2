package utils;

import java.sql.Connection;
import java.sql.ResultSet;

public abstract class SQL {
    protected static String TABLE_NAME = "abstract";
    protected static String DB_FILE_NAME = "abstract.db";

    protected Connection con;

    public SQL( String tableName,String dbFile){
        TABLE_NAME = tableName;
        DB_FILE_NAME= dbFile;
    }


    public ResultSet select(String columns, String condition) {
        return MySQLiteUtils.select(con, TABLE_NAME, columns, condition);
    }

    public void delete(String condition) {
        MySQLiteUtils.delete(con, TABLE_NAME, condition);
    }

    public void deleteAll() {
        MySQLiteUtils.deleteAll(con, TABLE_NAME);
    }

    public void update(String condition,Object... args) {
    }

    public void insert(Object... args) {
    }



    protected abstract String createValuesString(Object... params);
}
