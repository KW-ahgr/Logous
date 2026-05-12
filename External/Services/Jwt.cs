using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace External.Services;

public class JwtOptions
{
    public string Key { get; set; } = null!;
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public int AccessTokenMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 7;
}

public class RefreshToken
{
    public string TokenHash { get; set; } = null!;
    public string UserId { get; set; } = null!;
    public DateTime CreatedAtUtc { get; set; }
    public string CreatedByIp { get; set; } = null!;
    public DateTime ExpiresAtUtc { get; set; }
    public bool IsExpired => DateTime.UtcNow >= ExpiresAtUtc;
}

public interface IJwtService
{
    (string accessToken, DateTime expiresAtUtc, string jti) CreateAccessToken(string userId, string username,
        IEnumerable<string> roles);

    (string refreshTokenPlain, RefreshToken entity) CreateRefreshToken(string userId, string createdByIp);
    string Hash(string input);
}

public class JwtService : IJwtService
{
    private readonly SymmetricSecurityKey _key;
    private readonly JwtOptions _opt;

    public JwtService(IOptions<JwtOptions> opt)
    {
        _opt = opt.Value ?? throw new ArgumentNullException(nameof(opt));
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_opt.Key));
    }

    public (string accessToken, DateTime expiresAtUtc, string jti) CreateAccessToken(string userId, string username,
        IEnumerable<string> roles)
    {
        var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(_opt.AccessTokenMinutes);
        var jti = Guid.NewGuid().ToString("N");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.UniqueName, username),
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Name, username),
            new(JwtRegisteredClaimNames.Jti, jti),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var token = new JwtSecurityToken(
            _opt.Issuer,
            _opt.Audience,
            claims,
            now,
            expires,
            creds);

        var access = new JwtSecurityTokenHandler().WriteToken(token);
        return (access, expires, jti);
    }

    public (string refreshTokenPlain, RefreshToken entity) CreateRefreshToken(string userId, string createdByIp)
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        var plain = Convert.ToBase64String(bytes);

        var entity = new RefreshToken
        {
            TokenHash = Hash(plain),
            UserId = userId,
            CreatedAtUtc = DateTime.UtcNow,
            CreatedByIp = createdByIp,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_opt.RefreshTokenDays)
        };
        return (plain, entity);
    }

    public string Hash(string input)
    {
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}

public static class Hsh
{
    public static (string Hash, string Salt) HashPassword(string password)
    {
        var saltBytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }

        using (var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 100000, HashAlgorithmName.SHA256))
        {
            var hashBytes = pbkdf2.GetBytes(32);
            var hash = Convert.ToBase64String(hashBytes);
            var salt = Convert.ToBase64String(saltBytes);
            return (hash, salt);
        }
    }

    public static bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        var saltBytes = Convert.FromBase64String(storedSalt);
        using var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 100000, HashAlgorithmName.SHA256);
        var hashBytes = pbkdf2.GetBytes(32);
        var computedHash = Convert.ToBase64String(hashBytes);
        return computedHash == storedHash;
    }

    public static string HashPasswordWithSalt(string password, string saltBase64)
    {
        var saltBytes = Convert.FromBase64String(saltBase64);
        using var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 100000, HashAlgorithmName.SHA256);
        var hashBytes = pbkdf2.GetBytes(32);
        return Convert.ToBase64String(hashBytes);
    }
}