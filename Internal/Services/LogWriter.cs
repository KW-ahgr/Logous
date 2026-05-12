using System.Text.Json;
using Microsoft.Data.SqlClient;

namespace Internal.Services;

public sealed class LogWriter(IPermanentSqlConnection connection, ILogger<LogWriter> logger) : ILogWriter, IDisposable
{
    // private readonly JsonSerializerOptions _jsonOptions = new()
    // {
    //     PropertyNameCaseInsensitive = true,
    //     PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    // };

    private bool _disposed;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }

    public async Task WriteLogAsync(string jsonLog, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(jsonLog))
        {
            logger.LogWarning("Empty log received, skipping.");
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(jsonLog);
            var root = document.RootElement;

            var parameters = new
            {
                LevelId = GetInt(root, "LevelId"),
                Timestamp = GetDateTime(root, "Timestamp") ?? DateTime.UtcNow,
                Message = GetString(root, "Message") ?? string.Empty,
                CorrelationId = GetString(root, "CorrelationId"),
                PropertiesJson = GetString(root, "PropertiesJson") ?? GetRawText(root, "Properties"),
                UserDefinition = GetString(root, "UserDefinition"),
                ClientIp = GetString(root, "ClientIp") ?? "0.0.0.0",
                ClientPort = GetString(root, "ClientPort"),
                RequestPath = GetString(root, "RequestPath"),
                Protocol = GetString(root, "Protocol") ?? "Unknown"
            };

            await connection.ExecuteAsync("usp_AddLog", parameters, cancellationToken);
        }
        catch (JsonException ex)
        {
            logger.LogError(ex, "Invalid JSON received: {Json}", jsonLog);
            throw;
        }
        catch (SqlException ex)
        {
            logger.LogError(ex, "Database error while saving log");
            throw;
        }
    }

    private static string? GetString(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetString()
            : null;
    }

    private static int? GetInt(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetInt32()
            : null;
    }

    private static DateTime? GetDateTime(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetDateTime()
            : null;
    }

    private static string? GetRawText(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetRawText()
            : null;
    }
}

public interface ILogWriter
{
    Task WriteLogAsync(string jsonLog, CancellationToken cancellationToken = default);
}