using Confluent.Kafka;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace Internal.Receivers;

public sealed class KafkaReceiver(IOptions<KafkaSettings> settings, ILogger<KafkaReceiver> logger)
    : LogReceiverBase(logger)
{
    private readonly string _bootstrapServers = settings.Value.BootstrapServers!;
    private readonly string _groupId = settings.Value.GroupId!;
    private readonly string _topic = settings.Value.Topic!;
    private IConsumer<Ignore, string>? _consumer;

    protected override async Task ListenAsync(CancellationToken cancellationToken)
    {
        var config = new ConsumerConfig
        {
            BootstrapServers = _bootstrapServers,
            GroupId = _groupId,
            AutoOffsetReset = AutoOffsetReset.Earliest,
            EnableAutoCommit = false
        };

        _consumer = new ConsumerBuilder<Ignore, string>(config).Build();
        _consumer.Subscribe(_topic);

        Logger.LogInformation("Kafka Receiver started – Topic: {Topic}, Servers: {Servers}", _topic, _bootstrapServers);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
                try
                {
                    var consumeResult = _consumer.Consume(cancellationToken);
                    if (consumeResult?.Message?.Value != null)
                        try
                        {
                            await RaiseOnLogReceivedAsync(consumeResult.Message.Value, cancellationToken);
                        }
                        catch (SqlException e)
                        {
                            Logger.LogError(e, "Could not save log message: {MessageValue}",
                                consumeResult?.Message?.Value);
                        }

                    _consumer.Commit(consumeResult);
                }
                catch (ConsumeException ex)
                {
                    Logger.LogError(ex, "Kafka consume error");
                }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            _consumer?.Close();
        }
    }

    public override void Dispose()
    {
        _consumer?.Dispose();
    }
}