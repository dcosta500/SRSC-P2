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

    /**
     * Select from database
     * @param columns   the columns to be selected
     * @param condition the condition
     * @return The resulting set
     */
    public ResultSet select(String columns, String condition) {
        return MySQLiteUtils.select(con, TABLE_NAME, columns, condition);
    }


    /**
     * Delete from database
     * @param condition the condition
     */
    public void delete(String condition) {
        MySQLiteUtils.delete(con, TABLE_NAME, condition);
    }

    /**
     * Delete every entry from the database table
     */
    public void deleteAll() {
        MySQLiteUtils.deleteAll(con, TABLE_NAME);
    }

    /**
     * Update entry in the database
     * @param condition the condition
     * @param args the values to be updated
     */
    public abstract void update(String condition,Object... args);

    /**
     * insert entry in the database
     * @param args the values to be inserted
     */
    public abstract void insert(Object... args);

    /**
     * Transform values in string
     * @param params values
     * @return the values in string
     */
    protected abstract String createValuesString(Object... params);
}
