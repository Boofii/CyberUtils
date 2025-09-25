using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;

namespace CyberUtils;

/// <summary>
/// This class is used for creating an sql database that can be used to persistently store information.
/// It can be used to create tables and interact with them easily.
/// </summary>
public class DatabaseFragment
{
    public Action<string>? OnExecuted;

    private LoggerFragment? logger;
    private readonly string path;
    private DatabaseFormat? format;
    private SqliteConnection? connection;

    public DatabaseFragment(string name)
    {
        string temp = $"{name}.db";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            temp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), temp);
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            temp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), temp);
        else
            throw new Exception($"Couldn't create a database file with name: {name}, unsupported platform.");

        path = temp;
    }

    // Links a LoggerFragment with this DatabaseFragment.
    public DatabaseFragment WithLogger(LoggerFragment logger)
    {
        this.logger = logger;
        return this;
    }

    // Links a DatabaseFormat with this DatabaseFragment.
    public DatabaseFragment WithFormat(DatabaseFormat format)
    {
        this.format = format;
        return this;
    }

    // Establishes a database and connects to it.
    public void Establish()
    {
        try
        {
            connection = new SqliteConnection($"Data Source={path}");
            connection.Open();
            logger?.Log(LogLevel.INFO, $"Established a database at path: {path}.");

            if (format != null)
                NonQuery(format.ToString());
        }
        catch (Exception ex)
        {
            logger?.Log(LogLevel.ERROR, $"Failed to establish a database, {ex}.");
        }
    }

    // Executes a non-query sql command.
    public void NonQuery(string sql, string[]? keys = null, object[]? values = null)
    {
        if (connection == null)
            return;

        try
        {
            using var cmd = new SqliteCommand(sql, connection);
            if (keys != null && values != null)
                for (int i = 0; i < keys.Length; i++)
                    cmd.Parameters.AddWithValue(keys[i], values[i]);
            
            cmd.ExecuteNonQuery();
            OnExecuted?.Invoke(sql);
            logger?.Log(LogLevel.INFO, $"Executed an sql non query: {sql}.");
        }
        catch (Exception ex)
        {
            logger?.Log(LogLevel.ERROR, $"Failed to execute an sql non query: {sql}, {ex}.");
        }
    }

    // Executes a query sql command.
    public List<Dictionary<string, object>> Query(string sql, string[]? keys = null, object[]? values = null)
    {
        var results = new List<Dictionary<string, object>>();
        if (connection == null)
            return results;

        try
        {
            using var cmd = new SqliteCommand(sql, connection);
            if (keys != null && values != null)
                for (int i = 0; i < keys.Length; i++)
                    cmd.Parameters.AddWithValue(keys[i], values[i]);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var row = new Dictionary<string, object>();
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    row[reader.GetName(i)] = reader.GetValue(i);
                }
                results.Add(row);
            }
            OnExecuted?.Invoke(sql);
            logger?.Log(LogLevel.INFO, $"Executed an sql query: {sql}.");
        }
        catch (Exception ex)
        {
            logger?.Log(LogLevel.ERROR, $"Failed to execute an sql query: {sql}, {ex}.");
        }

        return results;
    }

    // If the primary type is an int, gets its maximum value from all the entries.
    public int GetMaxPrimary()
    {
        if (format != null && format.primaryType.Equals("INT"))
        {
            var result = Query($"SELECT IFNULL(MAX({format.primaryName}), -1) as Value FROM {format.name}");
            return Convert.ToInt32(result[0]["Value"]);
        }
        return -1;
    }

    // Closes the database connection.
    public void Close()
    {
        connection?.Close();
        connection = null;
    }
}

/// <summary>
/// This class is used to dynamically create table creation query.
/// The result is given by the ToString method.
/// </summary>
public class DatabaseFormat
{
    private static readonly string AdditionSign = "<|AA|>";

    public readonly string name;
    public readonly string primaryName;
    public readonly string primaryType;
    private string prompt;

    public DatabaseFormat(string name, string primaryName, string primaryType)
    {
        this.name = name;
        this.primaryName = primaryName;
        this.primaryType = primaryType.ToUpper();
        prompt = $"CREATE TABLE IF NOT EXISTS {name}({this.primaryName} {this.primaryType} PRIMARY KEY{AdditionSign})";
    }

    // Adds an argument to this DatabaseFormat based on its name and type.
    public DatabaseFormat AddArgument(string name, string type)
    {
        prompt = prompt.Replace(AdditionSign, $", {name} {type.ToUpper()}{AdditionSign}");
        return this;
    }

    // Converts this DatabaseFormat to a sql query repressented by a string.
    public override string ToString()
    {
        return prompt.Replace(AdditionSign, "");
    }
}