namespace Internal;

public class UdpSettings
{
    public bool Enabled { get; set; }
    public int Port { get; set; }
}

public class TcpSettings
{
    public bool Enabled { get; set; }
    public int Port { get; set; }
}

public class RabbitMqSettings
{
    public bool Enabled { get; set; }
    public string? HostName { get; set; }
    public int Port { get; set; }
    public string? UserName { get; set; }
    public string? Password { get; set; }
    public string? ExchangeName { get; set; }
    public string? QueueName { get; set; }
    public string? RoutingKey { get; set; }
}

public class KafkaSettings
{
    public bool Enabled { get; set; }
    public string? BootstrapServers { get; set; }
    public string? Topic { get; set; }
    public string? GroupId { get; set; }
}

public class DatabaseSettings
{
    public string DefaultConnection { get; set; } = string.Empty;
}