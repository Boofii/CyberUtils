using CyberUtils;

LoggerFragment logger1 = new LoggerFragment("client-1");
LoggerFragment logger2 = new LoggerFragment("client-2");
LoggerFragment logger3 = new LoggerFragment("client-3");
ClientFragment client1 = new ClientFragment("127.0.0.1", 4098).WithLogger(logger1);
ClientFragment client2 = new ClientFragment("127.0.0.1", 4098).WithLogger(logger2);
ClientFragment client3 = new ClientFragment("127.0.0.1", 4098).WithLogger(logger3);
CryptoFragment crypto1 = new CryptoFragment().WithClient(client1);
CryptoFragment crypto2 = new CryptoFragment().WithClient(client2);
CryptoFragment crypto3 = new CryptoFragment().WithClient(client3);
ServerFragment server = new ServerFragment("127.0.0.1", 4098, 10, 10);
CryptoFragment serverCrypto = new CryptoFragment().WithServer(server, "/home/boofi/public.pem", "/home/boofi/private.pem");

server.Establish();
client1.Connect();
client2.Connect();
client3.Connect();

for (int i = 0; i < 10; i++)
{
    Console.WriteLine($"<=== {i + 1} ===>");
    server.Execute("hello", []);
}
