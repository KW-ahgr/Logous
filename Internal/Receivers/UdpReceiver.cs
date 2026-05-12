using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;

namespace Internal.Receivers;

public sealed class UdpReceiver(IOptions<UdpSettings> settings, ILogger<UdpReceiver> logger) : LogReceiverBase(logger)
{
    private readonly int _port = settings.Value.Port;
    private UdpClient? _udpClient;

    protected override async Task ListenAsync(CancellationToken cancellationToken)
    {
        _udpClient = new UdpClient(_port);
        Logger.LogInformation("UDP Receiver listening on port {Port}", _port);

        while (!cancellationToken.IsCancellationRequested)
            try
            {
                var result = await _udpClient.ReceiveAsync(cancellationToken);
                var message = Encoding.UTF8.GetString(result.Buffer);
                await RaiseOnLogReceivedAsync(message, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error receiving UDP log");
            }
    }

    public override void Dispose()
    {
        _udpClient?.Dispose();
    }
}