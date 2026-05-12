namespace Internal.Receivers;

public interface ILogReceiver : IDisposable
{
    Task StartAsync(CancellationToken cancellationToken = default);
    Task StopAsync(CancellationToken cancellationToken = default);
    event Func<string, CancellationToken, Task>? OnLogReceived;
}