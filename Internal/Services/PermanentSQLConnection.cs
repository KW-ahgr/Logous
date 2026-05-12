using System.Data;
using Microsoft.Data.SqlClient;

namespace Internal.Services;

public interface IPermanentSqlConnection : IDisposable
{
    Task<int> ExecuteAsync(string storedProcedure, object parameters, CancellationToken cancellationToken = default);

    Task<T?> ExecuteScalarAsync<T>(string storedProcedure, object parameters,
        CancellationToken cancellationToken = default);
}

public class PermanentSqlConnection : IPermanentSqlConnection
{
    private readonly string _connectionString;
    private readonly Lock _lock = new();
    private SqlConnection? _connection;
    private bool _disposed;

    public PermanentSqlConnection(DatabaseSettings settings)
    {
        _connectionString = settings.DefaultConnection ??
                            throw new InvalidOperationException("Connection string 'DefaultConnection' is missing.");
        _ = EnsureConnectedAsync();
    }

    public async Task<int> ExecuteAsync(string storedProcedure, object? parameters,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            await using var cmd = new SqlCommand(storedProcedure, _connection);
            cmd.CommandType = CommandType.StoredProcedure;
            if (parameters == null) return await cmd.ExecuteNonQueryAsync(cancellationToken);
            foreach (var prop in parameters.GetType().GetProperties())
                cmd.Parameters.AddWithValue("@" + prop.Name, prop.GetValue(parameters) ?? DBNull.Value);
            return await cmd.ExecuteNonQueryAsync(cancellationToken);
        }, cancellationToken);
    }

    public async Task<T?> ExecuteScalarAsync<T>(string storedProcedure, object? parameters,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            await using var cmd = new SqlCommand(storedProcedure, _connection);
            cmd.CommandType = CommandType.StoredProcedure;
            if (parameters != null)
                foreach (var prop in parameters.GetType().GetProperties())
                    cmd.Parameters.AddWithValue("@" + prop.Name, prop.GetValue(parameters) ?? DBNull.Value);

            var result = await cmd.ExecuteScalarAsync(cancellationToken);
            return result == DBNull.Value ? default : (T?)result;
        }, cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _connection?.Dispose();
        _disposed = true;
    }

    private async Task EnsureConnectedAsync()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(PermanentSqlConnection));
        if (_connection != null && _connection.State == ConnectionState.Open)
            return;

        lock (_lock)
        {
            if (_connection is { State: ConnectionState.Open })
                return;
            _connection?.Dispose();
            _connection = new SqlConnection(_connectionString);
        }

        await _connection.OpenAsync();
    }

    private async Task<T> ExecuteWithRetryAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
    {
        var retryCount = 0;
        const int maxRetries = 3;
        var delay = TimeSpan.FromSeconds(1);

        while (true)
            try
            {
                await EnsureConnectedAsync();
                return await action();
            }
            catch (SqlException ex) when (IsTransientError(ex) && retryCount < maxRetries)
            {
                retryCount++;
                await Task.Delay(delay, cancellationToken);
                delay = TimeSpan.FromSeconds(delay.TotalSeconds * 2);
                _connection?.Dispose();
                _connection = null; // force reconnect next time
            }
    }

    private static bool IsTransientError(SqlException ex)
    {
        return ex.Number == -2 || // timeout expired
               ex.Number == 53 || // connection broken
               ex.Number == 0 || // network related
               ex.Number == 11001 || // host not found
               ex.Number == 10054; // connection reset by peer
    }
}