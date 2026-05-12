using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Internal.Receivers;

public sealed class RabbitMqReceiver(IOptions<RabbitMqSettings> settings, ILogger<RabbitMqReceiver> logger)
    : LogReceiverBase(logger), IDisposable
{
    private readonly string _exchangeName = settings.Value.ExchangeName!;
    private readonly string _host = settings.Value.HostName!;
    private readonly string _password = settings.Value.Password!;
    private readonly int _port = settings.Value.Port;
    private readonly string _queueName = settings.Value.QueueName!;
    private readonly string _routingKey = settings.Value.RoutingKey!;
    private readonly string _userName = settings.Value.UserName!;
    private IChannel? _channel;
    private IConnection? _connection;

    public override void Dispose()
    {
        _channel?.CloseAsync().GetAwaiter().GetResult();
        _channel?.Dispose();
        _connection?.CloseAsync().GetAwaiter().GetResult();
        _connection?.Dispose();
    }

    protected override async Task ListenAsync(CancellationToken cancellationToken)
    {
        var factory = new ConnectionFactory
        {
            HostName = _host,
            Port = _port,
            UserName = _userName,
            Password = _password,
            AutomaticRecoveryEnabled = true,
            NetworkRecoveryInterval = TimeSpan.FromSeconds(10)
        };

        _connection = await factory.CreateConnectionAsync(cancellationToken);
        _channel = await _connection.CreateChannelAsync(cancellationToken: cancellationToken);

        await _channel.ExchangeDeclareAsync(_exchangeName, ExchangeType.Topic, true,
            cancellationToken: cancellationToken);
        await _channel.QueueDeclareAsync(_queueName, true, false, false, cancellationToken: cancellationToken);
        await _channel.QueueBindAsync(_queueName, _exchangeName, _routingKey, cancellationToken: cancellationToken);

        var consumer = new AsyncEventingBasicConsumer(_channel);
        consumer.ReceivedAsync += async (_, ea) =>
        {
            var body = ea.Body.ToArray();
            var message = Encoding.UTF8.GetString(body);
            try
            {
                await RaiseOnLogReceivedAsync(message, cancellationToken);
            }
            catch (SqlException e)
            {
                Logger.LogError(e, "Could not save log message: {message}", message);
            }

            await _channel.BasicAckAsync(ea.DeliveryTag, false, cancellationToken);
        };

        await _channel.BasicConsumeAsync(_queueName, false, consumer, cancellationToken);

        Logger.LogInformation("RabbitMQ Receiver started – Exchange: {Exchange}, Queue: {Queue}", _exchangeName,
            _queueName);

        await Task.Delay(Timeout.Infinite, cancellationToken);
    }
}