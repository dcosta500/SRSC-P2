package utils;

import java.sql.Statement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.io.File;

public abstract class MySQLiteUtils {

    /**
     * Delete old db, and create new file
     * @param filename file of the db
     * @return Connection to the database
     */
    public static Connection resetFile(String filename) {
        try {
            // If it is empty, return connection.
            // If it is not empty, 
            Class.forName("org.sqlite.JDBC");
            String curDir = System.getProperty("user.dir");

            // Create folder if it does not exist
            File folder = new File(String.format("%s/db", curDir));
            if(!folder.exists())
                folder.mkdir();

            // Create file if it does not exist
            File file = new File(String.format("%s/db/%s", curDir, filename));
            if (file.exists() && file.length() > 0)
                file.delete();

            String jdbcUrl = String.format("jdbc:sqlite:%s", file.getAbsolutePath());
            return DriverManager.getConnection(jdbcUrl);
        } catch (Exception e) {
            System.out.println("SQLite: Could not reset file.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Create a table
     * @param conn  The connection to the database
     * @param tableName The table name to be created
     * @param columns The columns of the table, format: "uid TEXT PRIMARY KEY, password TEXT"
     */
    public static void createTable(Connection conn, String tableName, String columns) {
        try {
            Statement statement = conn.createStatement();
            statement.execute(String.format("CREATE TABLE %s (%s)", tableName, columns));
            statement.close();
        } catch (Exception e) {
            System.out.println("SQLite: Could not create table.");
            e.printStackTrace();
        }
    }

    /**
     * Select columns from a table
     * @param conn  The connection to the database
     * @param tableName The table name to be created
     * @param columns The columns of the table, format: "uid,password"
     * @param condition The condition of selection, format: "uid='1'"
     * @return The resulting query from the select
     */
    public static ResultSet select(Connection conn, String tableName, String columns, String condition) {
        try {
            String query = String.format("SELECT %s FROM %s WHERE %s", columns, tableName, condition);
            PreparedStatement ps = conn.prepareStatement(query);
            return ps.executeQuery();
        } catch (Exception e) {
            System.out.println("SQLite: Could not execute query.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Insert an entry into a table
     * @param conn  The connection to the database
     * @param tableName The table name to be created
     * @param columns The columns of the table, format: "uid,password"
     * @param values The values to be inserted, format: "name='alice', password='password'"
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
     * @param conn  The connection to the database
     * @param tableName The table name to be created
     * @param values The values to be inserted, format: "name='alice', password='password'"
     * @param condition The condition of selection, format: "uid='1'"
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
     * @param conn  The connection to the database
     * @param tableName The table name to be created
     * @param condition The condition of selection, format: "uid='1'"
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
     * @param conn  The connection to the database
     * @param tableName The table name to be created
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
