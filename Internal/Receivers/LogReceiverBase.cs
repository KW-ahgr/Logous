namespace Internal.Receivers;

public abstract class LogReceiverBase(ILogger logger) : ILogReceiver
{
    protected readonly ILogger Logger = logger;
    private CancellationTokenSource? _cts;

    public event Func<string, CancellationToken, Task>? OnLogReceived;

    public virtual async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Logger.LogInformation("{Receiver} starting...", GetType().Name);
        await ListenAsync(_cts.Token);
    }

    public virtual async Task StopAsync(CancellationToken cancellationToken = default)
    {
        _cts?.CancelAsync();
        await Task.CompletedTask;
        Logger.LogInformation("{Receiver} stopped.", GetType().Name);
    }

    public abstract void Dispose();

    protected abstract Task ListenAsync(CancellationToken cancellationToken);

    protected async Task RaiseOnLogReceivedAsync(string logMessage, CancellationToken cancellationToken)
    {
        if (OnLogReceived is not null)
            await OnLogReceived.Invoke(logMessage, cancellationToken);
    }
}