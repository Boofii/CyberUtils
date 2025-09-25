using System.Runtime.InteropServices;
using System.Text;

namespace CyberUtils;

/// <summary>
/// This class is used for logging messages to the console, and a file.
/// This provides users with the ability to scan for issues when running the application.
/// </summary>
public class LoggerFragment
{
    private static readonly Mutex mutex = new Mutex();
    private static readonly ConsoleColor[] Colors = [
        ConsoleColor.Green,
        ConsoleColor.Yellow,
        ConsoleColor.Red
    ];

    public Action<LogLevel, string>? OnLogged;

    private readonly string name;
    private readonly string path;

    // Creates a LoggerFragment, the name is used for naming the log file on disk.
    public LoggerFragment(string name)
    {
        this.name = name;
        string temp = $"{name}.log";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            temp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), temp);
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            temp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), temp);
        else
            throw new Exception($"Couldn't create a log file with name: {name}, unsupported platform.");

        path = temp;
    }

    // Logs a message to either/both the disk/console, based on the mode and the log level.
    public void Log(LogLevel level, string message, string mode = "cd")
    {
        mutex.WaitOne();
        FileStream file = File.Exists(path) ? File.Open(path, FileMode.Append) : File.Create(path);
        string actMessage = $"[{name}, {level}]: {message}";

        if (mode.Contains('c'))
        {
            ConsoleColor color = Colors[(int)level];
            Console.ForegroundColor = color;
            Console.WriteLine(actMessage);
            Console.ForegroundColor = ConsoleColor.White;
        }
        if (mode.Contains('d'))
        {
            byte[] buffer = Encoding.UTF8.GetBytes(actMessage + '\n');
            file.Write(buffer);
        }

        file.Dispose();
        OnLogged?.Invoke(level, message);
        mutex.ReleaseMutex();
    }
}

/// <summary>
/// This class is provided as an argument to the LoggerFragment.Log method.
/// It controls the color and text that is used when logging.
/// </summary>
public enum LogLevel
{
    INFO,
    WARNING,
    ERROR
}