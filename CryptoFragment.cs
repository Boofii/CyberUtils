using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CyberUtils;

/// <summary>
/// This class is used to wrap a ServerFragment or a ClientFragment with a secure connection.
/// The sender always encrypts messages before they are sent and the receiver decrypts them.
/// It is important for the CryptoFragment to be initialized before the ServerFragment and the ClientFragment.
/// </summary>
public class CryptoFragment
{
    private LoggerFragment? logger;
    private Dictionary<int, RSA>? keys;
    private ServerFragment? server;
    private string? publicPath;
    private RSA? publicKey;
    private RSA? privateKey;
    private RSA? clientPrivateKey;

    // Links a LoggerFragment with this CryptoFragment.
    public CryptoFragment WithLogger(LoggerFragment logger)
    {
        this.logger = logger;
        return this;
    }

    // Links a ServerFragment with this CryptoFragment, the private path should include a pem file.
    public CryptoFragment WithServer(ServerFragment server, string publicPath, string privatePath)
    {
        this.publicPath = publicPath;
        this.keys = [];
        this.server = server;
        server.OnConnection += OnServerConnection;
        server.OnReceived += OnServerReceived;
        server.DoEncryption += EncryptServer;
        server.DoDecryption += DecryptServer;

        try
        {
            RSA rsa = RSA.Create();
            string content = File.ReadAllText(privatePath);
            rsa.ImportFromPem(content);
            this.privateKey = rsa;
        }
        catch (Exception ex)
        {
            logger?.Log(LogLevel.ERROR, $"Failed to set up a CryptoFragment for server: {ex}.");
        }
        return this;
    }

    // Links a ClientFragment with this CryptoFragment, the public path should include a pem file.
    public CryptoFragment WithClient(ClientFragment client)
    {
        client.DoEncryption += EncryptClient;
        client.DoDecryption += DecryptClient;
        client.OnConnection += OnClientConnection;
        client.OnReceived += OnClientReceived;
        return this;
    }

    // Encrypts a message using the public key of the server.
    public byte[] EncryptClient(byte[] buffer)
    {
        if (publicKey == null)
        {
            logger?.Log(LogLevel.ERROR, "Tried to encrypt data for client but an RSA public key was missing.");
            return [];
        }

        byte[] encryption = publicKey.Encrypt(buffer, RSAEncryptionPadding.OaepSHA256);
        return encryption;
    }

    // Encrypts a message using the public key of the client.
    public byte[] EncryptServer(int id, byte[] buffer)
    {
        if (keys == null)
            return [];

        RSA rsa = keys[id];
        byte[] encryption = rsa.Encrypt(buffer, RSAEncryptionPadding.OaepSHA256);
        return encryption;
    }

    // Decrypts a message using the private key of the server.
    public byte[] DecryptServer(byte[] buffer)
    {
        string message = Encoding.UTF8.GetString(buffer);
        if (message.StartsWith("public_key"))
            return buffer;

        if (privateKey == null)
        {
            logger?.Log(LogLevel.ERROR, "Tried to decrypt data for server but an RSA private key was missing.");
            return [];
        }

        byte[] decryption = privateKey.Decrypt(buffer, RSAEncryptionPadding.OaepSHA256);
        return decryption;
    }

    // Decrypts a message using the private key of the client.
    public byte[] DecryptClient(byte[] buffer)
    {
        string message = Encoding.UTF8.GetString(buffer);
        if (message.StartsWith("public_key"))
            return buffer;

        if (clientPrivateKey == null)
        {
            logger?.Log(LogLevel.ERROR, "Tried to decrypt data for client but an RSA private key was missing.");
            return [];
        }

        byte[] decryption = clientPrivateKey.Decrypt(buffer, RSAEncryptionPadding.OaepSHA256);
        return decryption;
    }

    // Hashes a string (Sha-256).
    public byte[] Hash(string str)
    {
        byte[] buffer = Encoding.UTF8.GetBytes(str);
        byte[] result = SHA256.HashData(buffer);
        return result;
    }

    // Provides a newly connected client with the server's public key.
    private void OnServerConnection(int id, Socket client)
    {
        if (publicPath != null)
        {
            logger?.Log(LogLevel.INFO, $"public key => client {id}.");
            string content = File.ReadAllText(publicPath);
            string message = $"public_key<|EON|>{content}{ServerFragment.EndSign}";
            byte[] buffer = Encoding.UTF8.GetBytes(message);
            client.Send(buffer);
        }
    }

    // Provides the server with a newly generated and unique client's public key.
    private void OnClientConnection(Socket client)
    {
        logger?.Log(LogLevel.INFO, "public key => server.");
        RSA rsa = RSA.Create(2048);
        this.clientPrivateKey = rsa;
        string content = rsa.ExportRSAPublicKeyPem();
        string message = $"public_key<|EON|>{content}{ClientFragment.EndSign}";
        byte[] buffer = Encoding.UTF8.GetBytes(message);
        client.Send(buffer);
    }

    // Receives the server's public key.
    private void OnClientReceived(string cmd, string[] args)
    {
        if (cmd.Equals("public_key"))
        {
            logger?.Log(LogLevel.INFO, "public key received.");
            try
            {
                RSA rsa = RSA.Create();
                string content = args[0];
                rsa.ImportFromPem(content);
                this.publicKey = rsa;
            }
            catch (Exception ex)
            {
                logger?.Log(LogLevel.ERROR, $"Failed to set up a CryptoFragment for client: {ex}.");
            }
        }
    }

    // Receives the client's public key.
    private void OnServerReceived(string cmd, string[] args)
    {
        if (cmd.Equals("public_key") && server != null && keys != null)
        {
            logger?.Log(LogLevel.INFO, "public key received.");
            RSA rsa = RSA.Create();
            string content = args[0];
            rsa.ImportFromPem(content);
            this.keys[keys.Count] = rsa;
        }
    }

    // Closes the RSA connections.
    public void Close()
    {
        publicKey?.Dispose();
        privateKey?.Dispose();
        if (keys != null)
            foreach (RSA rsa in keys.Values)
                rsa.Dispose();
    }
}