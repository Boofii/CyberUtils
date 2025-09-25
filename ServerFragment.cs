using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CyberUtils;

/// <summary>
/// This class is used for creating a tcp server that listens for commands from the client.
/// It can also execute commands that will be sent to the client and processed there.
/// </summary>
public class ServerFragment
{
    public static readonly string EndSign = "<|EOM|>";
    public static readonly string ArgSign = "<|EON|>";
    public static readonly string SepSign = "<|EOA|>";

    public readonly Dictionary<int, Socket> connections = [];
    public Action<int, Socket>? OnConnection;
    public Action<string, string[]>? OnSent;
    public Action<string, string[]>? OnReceived;
    public Func<int, byte[], byte[]>? DoEncryption;
    public Func<byte[], byte[]>? DoDecryption;

    private LoggerFragment? logger;
    private readonly string address;
    private readonly int port;
    private readonly int maxQueue;
    private readonly int maxConnections;
    private int currConnection = 0;
    private Socket? server;

    public ServerFragment(string address, int port, int maxQueue = 10, int maxConnections = 10)
    {
        this.address = address;
        this.port = port;
        this.maxQueue = maxQueue;
        this.maxConnections = maxConnections;
    }

    // Links a LoggerFragment with this ServerFragment.
    public ServerFragment WithLogger(LoggerFragment logger)
    {
        this.logger = logger;
        return this;
    }

    // Establishes a server and listens for commands from the client.
    public void Establish()
    {
        try
        {
            IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(address), port);
            server = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            server.Bind(endPoint);
            server.Listen(maxQueue);

            Thread acceptingThread = new Thread(() =>
            {
                while (currConnection < maxConnections)
                {
                    Socket client = server.Accept();
                    logger?.Log(LogLevel.INFO, $"Established a connection with client: {currConnection}.");
                    Thread listeningThread = new Thread(() =>
                    {
                        try
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
                        }
                        catch (Exception ex)
                        {
                            logger?.Log(LogLevel.WARNING, $"One client had disconnected: {ex}.");
                        }
                        finally
                        {
                            client.Close();
                            foreach (int id in connections.Keys)
                                if (connections[id].Equals(client))
                                    connections.Remove(id);
                        }
                    });
                    listeningThread.Start();
                    connections[currConnection] = client;
                    OnConnection?.Invoke(currConnection, client);
                    currConnection++;
                }
            });
            acceptingThread.Start();
        }
        catch (Exception ex)
        {
            logger?.Log(LogLevel.ERROR, $"Failed to establish a server, {ex}.");
        }
    }

    // Executes a command based on its name and args.
    public void Execute(string cmd, string[] args, int id = -1)
    {
        byte[] buffer = Encoding.UTF8.GetBytes($"{cmd}{(args.Length > 0 ? ArgSign + string.Join(SepSign, args) : "")}{EndSign}");

        if (id == -1)
        {
            foreach (int clientId in connections.Keys)
                if (DoEncryption != null)
                    connections[clientId].Send(DoEncryption(clientId, buffer));
                else
                    connections[clientId].Send(buffer);
        }
        else
        {
            if (DoEncryption != null)
                connections[id].Send(DoEncryption(id, buffer));
            else
                connections[id].Send(buffer);
        }
        OnSent?.Invoke(cmd, args);
        Thread.Sleep(1);
    }

    // Closes the server socket.
    public void Close()
    {
        server?.Close();
        server = null;
    }

    // A utility method to fix the blank characters occuring after the end of data.
    public static string Netfix(string str)
    {
        int endIndex = str.IndexOf(EndSign);
        string newStr = str.Substring(0, endIndex);
        return newStr;
    }
}