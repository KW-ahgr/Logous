using Internal.Receivers;

namespace Internal.Services;

public class UdpReceiverService(UdpReceiver receiver, ILogWriter logWriter) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        receiver.OnLogReceived += async (log, ct) => await logWriter.WriteLogAsync(log, ct);
        await receiver.StartAsync(stoppingToken);
        // await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await receiver.StopAsync(cancellationToken);
        await base.StopAsync(cancellationToken);
    }
}

public class TcpReceiverService(TcpReceiver receiver, ILogWriter logWriter) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        receiver.OnLogReceived += async (log, ct) => await logWriter.WriteLogAsync(log, ct);
        await receiver.StartAsync(stoppingToken);
        // await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await receiver.StopAsync(cancellationToken);
        await base.StopAsync(cancellationToken);
    }
}

public class RabbitMqReceiverService(RabbitMqReceiver receiver, ILogWriter logWriter) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        receiver.OnLogReceived += async (log, ct) => await logWriter.WriteLogAsync(log, ct);
        await receiver.StartAsync(stoppingToken);
        // await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await receiver.StopAsync(cancellationToken);
        await base.StopAsync(cancellationToken);
    }
}

public class KafkaReceiverService(KafkaReceiver receiver, ILogWriter logWriter) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        receiver.OnLogReceived += async (log, ct) => await logWriter.WriteLogAsync(log, ct);
        await receiver.StartAsync(stoppingToken);
        // await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await receiver.StopAsync(cancellationToken);
        await base.StopAsync(cancellationToken);
    }
}