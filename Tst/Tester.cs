using System.Net.Sockets;
using System.Text;
using External.Models;
using Internal;
using Internal.Receivers;
using Internal.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestPlatform.TestHost;
using Moq;
using Testcontainers.MsSql;
using DatabaseSettings = External.DatabaseSettings;

namespace Tst;

using External.Services;
using Xunit;

public class HshTests
{
    [Fact]
    public void HashPassword_ProducesDifferentHashForSamePassword_WithDifferentSalt()
    {
        var (hash1, salt1) = Hsh.HashPassword("MyPass123");
        var (hash2, salt2) = Hsh.HashPassword("MyPass123");

        Assert.NotEqual(hash1, hash2);
        Assert.NotEqual(salt1, salt2);
    }

    [Fact]
    public void VerifyPassword_Success_WhenCorrect()
    {
        var password = "SecureP@ss";
        var (hash, salt) = Hsh.HashPassword(password);
        var result = Hsh.VerifyPassword(password, hash, salt);
        Assert.True(result);
    }

    [Fact]
    public void VerifyPassword_Fails_WhenWrong()
    {
        var (hash, salt) = Hsh.HashPassword("Correct");
        var result = Hsh.VerifyPassword("Wrong", hash, salt);
        Assert.False(result);
    }
}


public class JwtServiceTests
{
    private readonly JwtService _jwtService;
    public JwtServiceTests()
    {
        var options = Options.Create(new JwtOptions
        {
            Key = "ThisIsA32ByteLongKeyForTestingPurposes!!",
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenMinutes = 15,
            RefreshTokenDays = 7
        });
        _jwtService = new JwtService(options);
    }

    [Fact]
    public void CreateAccessToken_ReturnsValidToken()
    {
        var (token, expiresAt, jti) = _jwtService.CreateAccessToken("user-123", "alice", new[] { "Admin" });
        Assert.NotNull(token);
        Assert.True(expiresAt > DateTime.UtcNow);
        Assert.NotNull(jti);
    }

    [Fact]
    public void CreateRefreshToken_ReturnsPlainAndHashed()
    {
        var (plain, entity) = _jwtService.CreateRefreshToken("user-123", "127.0.0.1");
        Assert.NotNull(plain);
        Assert.NotNull(entity.TokenHash);
        Assert.Equal("user-123", entity.UserId);
        Assert.Equal("127.0.0.1", entity.CreatedByIp);
        Assert.False(entity.IsExpired);
    }

    [Fact]
    public void Hash_IsDeterministic()
    {
        var input = "testString";
        var hash1 = _jwtService.Hash(input);
        var hash2 = _jwtService.Hash(input);
        Assert.Equal(hash1, hash2);
    }
}


public class StoredProcedureServiceTests
{
    [Fact]
    public async Task ExecuteJsonAsync_ReturnsJson_WhenConnectionReturnsValue()
    {
        var mockConnection = new Mock<IPermanentSqlConnection>();
        mockConnection
            .Setup(x => x.ExecuteScalarAsync<string>(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync("{\"key\":\"value\"}");

        var service = new StoredProcedureService(mockConnection.Object);
        var result = await service.ExecuteJsonAsync("SomeProc", new { Id = 1 });

        Assert.Equal("{\"key\":\"value\"}", result);
    }

    [Fact]
    public async Task ExecuteJsonAsync_ReturnsDefault_WhenNull()
    {
        var mockConnection = new Mock<IPermanentSqlConnection>();
        mockConnection
            .Setup(x => x.ExecuteScalarAsync<string>(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        var service = new StoredProcedureService(mockConnection.Object);
        var result = await service.ExecuteJsonAsync("SomeProc", null, def: "{}");

        Assert.Equal("{}", result);
    }
}


public class CustomWebApplicationFactory : WebApplicationFactory<Program> 
{
    public Mock<IPermanentSqlConnection> MockConnection { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IPermanentSqlConnection));
            if (descriptor != null) services.Remove(descriptor);

            services.AddSingleton(MockConnection.Object);
        });
    }
}


// public class AuthControllerTests : IClassFixture<CustomWebApplicationFactory>
// {
//     private readonly CustomWebApplicationFactory _factory;
//     public AuthControllerTests(CustomWebApplicationFactory factory) => _factory = factory;
//
//     [Fact]
//     public async Task Login_ReturnsOk_WhenCredentialsCorrect()
//     {
//         var client = _factory.MockConnection();
//         var mockConnection = _factory.MockConnection;
//
//         mockConnection
//             .Setup(x => x.ExecuteScalarAsync<string>("usp_GetUserSalt", It.IsAny<object>(), It.IsAny<CancellationToken>()))
//             .ReturnsAsync("{\"UserSalt\":{\"Salt\":\"abc123\"}}");
//
//         mockConnection
//             .Setup(x => x.ExecuteScalarAsync<string>("usp_TryLogin", It.IsAny<object>(), It.IsAny<CancellationToken>()))
//             .ReturnsAsync("{\"Users\":[{\"Uid\":\"123e4567-e89b-12d3-a456-426614174000\",\"Username\":\"testuser\",\"Role\":\"Viewer\"}]}");
//
//         mockConnection
//             .Setup(x => x.ExecuteAsync("usp_SetUserRefreshToken", It.IsAny<object>(), It.IsAny<CancellationToken>()))
//             .ReturnsAsync(1);
//
//         var request = new LoginRequest() { Username = "testuser", Password = "pass" };
//
//         var response = await client.PostAsJsonAsync("/api/Auth/login", request);
//         var content = await response.Content.ReadAsStringAsync();
//
//         Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
//         Assert.Contains("AccessToken", content);
//     }
// }
//
// public class LogWriterTests
// {
//     [Fact]
//     public async Task WriteLogAsync_CallsExecuteAsync_WithCorrectParameters()
//     {
//         var mockConnection = new Mock<IPermanentSqlConnection>();
//         var logger = NullLogger<LogWriter>.Instance;
//         var writer = new LogWriter(mockConnection.Object, logger);
//
//         string json = @"{""LevelId"":5,""Timestamp"":""2025-01-01T12:00:00"",""Message"":""test"",""ClientIp"":""10.0.0.1""}";
//
//         await writer.WriteLogAsync(json);
//
//         mockConnection.Verify(
//             x => x.ExecuteAsync("usp_AddLog", It.IsAny<object>(), It.IsAny<CancellationToken>()),
//             Times.Once);
//     }
//
//     [Fact]
//     public async Task WriteLogAsync_HandlesInvalidJson_Throws()
//     {
//         var mockConnection = new Mock<IPermanentSqlConnection>();
//         var logger = NullLogger<LogWriter>.Instance;
//         var writer = new LogWriter(mockConnection.Object, logger);
//
//         await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => writer.WriteLogAsync("{ invalid json }"));
//     }
// }
//
// public class UdpReceiverTests : IDisposable
// {
//     private readonly int _testPort = 15123;
//     private readonly UdpReceiver _receiver;
//     public UdpReceiverTests()
//     {
//         var settings = new UdpSettings() { Enabled = true, Port = _testPort };
//         var logger = NullLogger.Instance;
//         _receiver = new UdpReceiver(settings, logger);
//     }
//
//     [Fact]
//     public async Task StartAsync_ReceivesMessageAndRaisesEvent()
//     {
//         var tcs = new TaskCompletionSource<string>();
//         _receiver.OnLogReceived += (msg, ct) =>
//         {
//             tcs.SetResult(msg);
//             return Task.CompletedTask;
//         };
//
//         var cts = new CancellationTokenSource();
//
//         _ = _receiver.StartAsync(cts.Token);
//
//         await Task.Delay(100, cts.Token);
//
//         using var client = new UdpClient();
//         var message = "Test log message";
//         var bytes = Encoding.UTF8.GetBytes(message);
//         await client.SendAsync(bytes, bytes.Length, "127.0.0.1", _testPort);
//
//         var received = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
//         Assert.Equal(message, received);
//
//         await cts.CancelAsync();
//     }
//
//     public void Dispose()
//     {
//         _receiver.Dispose();
//     }
// }


public class DatabaseIntegrationTests(MsSqlContainer sqlContainer, string connectionString) : IAsyncLifetime
{
    private MsSqlContainer _sqlContainer = sqlContainer ?? throw new ArgumentNullException(nameof(sqlContainer));
    private string _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));

    [Obsolete("Obsolete")]
    public async Task InitializeAsync()
    {
        _sqlContainer = new MsSqlBuilder()
            .WithImage("mcr.microsoft.com/mssql/server:2022-latest")
            .WithPassword("YourStrong!Password")
            .Build();
        await _sqlContainer.StartAsync();
        _connectionString = _sqlContainer.GetConnectionString();
    }

    [Fact]
    public async Task PermanentSqlConnection_CanExecuteScalar()
    {
        var settings = new DatabaseSettings() { DefaultConnection = _connectionString };
        using var conn = new PermanentSqlConnection(settings);
        var result = await conn.ExecuteScalarAsync<int>("SELECT 1+1", null);
        Assert.Equal(2, result);
    }

    public async Task DisposeAsync()
    {
        await _sqlContainer.DisposeAsync();
    }
}
