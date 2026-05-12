namespace External.Services;

public interface ILogService
{
    Task<string> ExecuteJsonAsync(string storedProcedure, object? parameters = null,
        CancellationToken cancellationToken = default, string def = "{}");
}

public class StoredProcedureService(IPermanentSqlConnection connection) : ILogService
{
    public async Task<string> ExecuteJsonAsync(string storedProcedure, object? parameters = null,
        CancellationToken cancellationToken = default, string def = "{}")
    {
        var json = await connection.ExecuteScalarAsync<string>(storedProcedure, parameters!, cancellationToken);
        return json ?? def;
    }
}