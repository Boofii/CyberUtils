using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CyberUtils;

/// <summary>
/// This class is used for creating a tcp client that listens for commands from the server.
/// It can also execute commands that will be sent to the server and processed there.
/// </summary>
public class ClientFragment
{
    public static readonly string EndSign = "<|EOM|>";
    public static readonly string ArgSign = "<|EON|>";
    public static readonly string SepSign = "<|EOA|>";

    public Action<Socket>? OnConnection;
    public Action<string, string[]>? OnSent;
    public Action<string, string[]>? OnReceived;
    public Func<byte[], byte[]>? DoEncryption;
    public Func<byte[], byte[]>? DoDecryption;

    private LoggerFragment? logger;
    private readonly string serverAddress;
    private readonly int serverPort;
    private Socket? client;

    // Links a LoggerFragment with this ClientFragment.
    public ClientFragment(string serverAddress, int serverPort)
    {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
    }

    // Links a LoggerFragment with this ServerFragment.
    public ClientFragment WithLogger(LoggerFragment logger)
    {
        this.logger = logger;
        return this;
    }

    // Connects to a server and listens for commands from it.
    public void Connect()
    {
        try
        {
            IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(serverAddress), serverPort);
            client = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(endPoint);
            logger?.Log(LogLevel.INFO, $"Connected to the server with address, port: {serverAddress}, {serverPort}.");

            Thread listeningThread = new Thread(() =>
            {
                while (true)
                {
                    byte[] buffer = new byte[1024];
                    int amount = client.Receive(buffer);
                    buffer = [.. buffer.Take(amount)];
                    if (DoDecryption != null)
                        buffer = DoDecryption(buffer);

                    string cmd = Encoding.UTF8.GetString(buffer);
                    if (cmd.Contains(EndSign))
                    {
                        cmd = ServerFragment.Netfix(cmd);
                        string[] splitCmd = cmd.Split(ArgSign);
                        string name = splitCmd[0];
                        string[] args = [];
                        if (splitCmd.Length > 1)
                            args = splitCmd[1].Split(SepSign);

                        if (!name.StartsWith("public_key"))
                            logger?.Log(LogLevel.INFO, $"Received a command: {cmd}.");
                        OnReceived?.Invoke(name, args);
                    }
                }
            });
            listeningThread.Start();
            OnConnection?.Invoke(client);
            Thread.Sleep(10);
        }
        catch (Exception ex)
        {
            logger?.Log(LogLevel.ERROR, $"Failed to connect to a server, {ex}.");
        }
    }

    // Executes a command based on its name and args.
    public void Execute(string cmd, string[] args)
    {
        byte[] buffer = Encoding.UTF8.GetBytes($"{cmd}{(args.Length > 0 ? ArgSign + string.Join(SepSign, args) : "")}{EndSign}");
        if (DoEncryption != null)
            buffer = DoEncryption(buffer);

        client?.Send(buffer);
        OnSent?.Invoke(cmd, args);
        Thread.Sleep(1);
    }

    // Closes the client socket.
    public void Close()
    {
        client?.Close();
        client = null;
    }
}