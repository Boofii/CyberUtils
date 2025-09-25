using System.Net;
using System.Net.Mail;

namespace CyberUtils;

/// <summary>
/// This class is used for interacting with the gmail smtp server.
/// It can be used to send emails in a secure way 
/// </summary>
public class EmailFragment
{
    public Action<MailMessage>? OnSent;

    private LoggerFragment? logger;
    private readonly string server;
    private readonly string provider;
    private readonly int port;
    private readonly string password;
    private readonly bool useSsl;

    public EmailFragment(string provider, string password, bool useSsl)
    {
        this.server = "smtp.gmail.com";
        this.provider = provider;
        this.port = 587;
        this.password = password;
        this.useSsl = useSsl;
    }

    // Links a LoggerFragment with this EmailFragment.
    public EmailFragment WithLogger(LoggerFragment logger)
    {
        this.logger = logger;
        return this;
    }

    // Sends an email to the specified address and body.
    public void Send(string address, string subject, string body)
    {
        string actBody = !body.Contains("<html>") ? $"<html><body>{body}</body></html>" : body;

        SmtpClient client = new SmtpClient()
        {
            Host = server,
            Port = port,
            EnableSsl = useSsl,
            Credentials = new NetworkCredential(provider, password)
        };
        MailMessage message = new MailMessage()
        {
            From = new MailAddress(provider),
            Subject = subject,
            Body = actBody,
            IsBodyHtml = true
        };
        message.To.Add(new MailAddress(address));

        client.Send(message);
        logger?.Log(LogLevel.INFO, $"Sent an email to address: {address}.");
        OnSent?.Invoke(message);
        client.Dispose();
    }
}