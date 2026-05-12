using Internal;
using Internal.Receivers;
using Internal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<ILogWriter, LogWriter>();

builder.Services.Configure<DatabaseSettings>(builder.Configuration.GetSection("DatabaseSettings"));
builder.Services.AddSingleton<IPermanentSqlConnection, PermanentSqlConnection>();

var udpSection = builder.Configuration.GetSection("Udp");
if (udpSection.Exists() && udpSection.GetValue<bool?>("Enabled") == true)
{
    builder.Services.Configure<UdpSettings>(udpSection);
    builder.Services.AddSingleton<UdpReceiver>();
    builder.Services.AddHostedService<UdpReceiverService>();
}

var tcpSection = builder.Configuration.GetSection("Tcp");
if (tcpSection.Exists() && tcpSection.GetValue<bool?>("Enabled") == true)
{
    builder.Services.Configure<TcpSettings>(tcpSection);
    builder.Services.AddSingleton<TcpReceiver>();
    builder.Services.AddHostedService<TcpReceiverService>();
}

var rabbitMqSection = builder.Configuration.GetSection("RabbitMq");
if (rabbitMqSection.Exists() && rabbitMqSection.GetValue<bool?>("Enabled") == true)
{
    builder.Services.Configure<RabbitMqSettings>(rabbitMqSection);
    builder.Services.AddSingleton<RabbitMqReceiver>();
    builder.Services.AddHostedService<RabbitMqReceiverService>();
}

var kafkaSection = builder.Configuration.GetSection("Kafka");
if (kafkaSection.Exists() && kafkaSection.GetValue<bool?>("Enabled") == true)
{
    builder.Services.Configure<KafkaSettings>(kafkaSection);
    builder.Services.AddSingleton<KafkaReceiver>();
    builder.Services.AddHostedService<KafkaReceiverService>();
}

var app = builder.Build();

app.Run();