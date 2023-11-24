package utils;

import java.sql.Statement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.io.File;

public abstract class MySQLiteUtils {

    /**
     * Delete old db, and create new file
     * return Connection to that file
     */
    public static Connection resetFile(String filename) {
        try {
            // If it is empty, return connection.
            // If it is not empty, 
            Class.forName("org.sqlite.JDBC");
            String curDir = System.getProperty("user.dir");

            File file = new File(String.format("%s/db/%s", curDir, filename));

            if (file.exists() && file.length() > 0)
                file.delete();

            String jdbcUrl = String.format("jdbc:sqlite:%s", file.getAbsolutePath());
            Connection conn = DriverManager.getConnection(jdbcUrl);

            return conn;
        } catch (Exception e) {
            System.out.println("SQLite: Could not reset file.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Create a table
     * Example Values = "uid TEXT PRIMARY KEY, password TEXT"
     */
    public static void createTable(Connection conn, String tableName, String values) {
        try {
            Statement statement = conn.createStatement();
            statement.execute(String.format("CREATE TABLE %s (%s)", tableName, values));
            statement.close();
        } catch (Exception e) {
            System.out.println("SQLite: Could not create table.");
            e.printStackTrace();
        }
    }

    /**
     * Insert an entry into a table
     * Example Columns = "uid,password"
     * Example Values = "'a', 'b'"
     */
    public static void insert(Connection conn, String tableName, String columns, String values) {
        try {
            Statement statement = conn.createStatement();
            statement.execute(String.format("INSERT INTO %s (%s) VALUES (%s)", tableName, columns, values));
        } catch (Exception e) {
            System.out.println("SQLite: Could not insert row.");
            e.printStackTrace();
        }
    }

    /**
     * Update an entry in a table
     * Example Values = "name='alice', password='password'"
     * Example primaryKeyCondition = "uid='1'"
     */
    public static void update(Connection conn, String tableName, String values, String condition) {
        try {
            Statement statement = conn.createStatement();
            statement.execute(
                    String.format("UPDATE %s SET VALUES (%s) WHERE %s", tableName, values, condition));
            statement.close();
        } catch (Exception e) {
            System.out.println("SQLite: Could not update row(s).");
            e.printStackTrace();
        }
    }

    /**
     * Delete a single entry in a table
     * Example primaryKeyCondition = "uid='1'"
     */
    public static void delete(Connection conn, String tableName, String condition) {
        try {
            Statement statement = conn.createStatement();
            statement.execute(String.format("DELETE FROM %s WHERE %s", tableName, condition));
            statement.close();
        } catch (Exception e) {
            System.out.println("SQLite: Could not delete row(s).");
            e.printStackTrace();
        }
    }

    /**
     * Delete all entrys in a table
     */
    public static void deleteAll(Connection conn, String tableName) {
        try {
            Statement statement = conn.createStatement();
            statement.execute(String.format("DELETE FROM %s", tableName));
            statement.close();
        } catch (Exception e) {
            System.out.println("SQLite: Could not delete all rows from table.");
            e.printStackTrace();
        }
    }
}
