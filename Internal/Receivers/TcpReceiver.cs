using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;

namespace Internal.Receivers;

public sealed class TcpReceiver(IOptions<TcpSettings> settings, ILogger<TcpReceiver> logger) : LogReceiverBase(logger)
{
    private readonly int _port = settings.Value.Port;
    private TcpListener? _listener;

    protected override async Task ListenAsync(CancellationToken cancellationToken)
    {
        _listener = new TcpListener(IPAddress.Any, _port);
        _listener.Start();
        Logger.LogInformation("TCP Receiver listening on port {Port}", _port);

        while (!cancellationToken.IsCancellationRequested)
            try
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                _ = HandleClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error accepting TCP client");
            }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        await using (var stream = client.GetStream())
        using (var reader = new StreamReader(stream, Encoding.UTF8, false, 4096, false))
        {
            try
            {
                while (await reader.ReadLineAsync(cancellationToken) is { } line)
                    if (!string.IsNullOrWhiteSpace(line))
                        await RaiseOnLogReceivedAsync(line, cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error handling TCP client");
            }
        }
    }

    public override void Dispose()
    {
        _listener?.Stop();
    }
}