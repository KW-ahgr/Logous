using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using External.Models;
using External.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace External.Controllers;

using static Hsh;

[ApiController]
[Route("api/Auth")]
public class AuthController(PermanentSqlConnection connection, ILogService service, IJwtService jwtService, ILogger<AuthController> logger)
    : ControllerBase
{
    /// <summary>
    /// Retrieves a list of users with optional filtering (Admin only)
    /// </summary>
    /// <param name="uid">Filter by user ID</param>
    /// <param name="username">Filter by username (exact match)</param>
    /// <param name="email">Filter by email (exact match)</param>
    /// <param name="phoneNumber">Filter by phone number (exact match)</param>
    /// <param name="details">Filter by details (exact match)</param>
    /// <param name="role">Filter by user role (Viewer, Admin, Auditor)</param>
    /// <param name="isActive">Filter by active status</param>
    /// <param name="page">Page number (default: 1)</param>
    /// <param name="pageSize">Items per page (default: 2500)</param>
    /// <response code="200">Returns JSON array of users</response>
    /// <response code="401">Missing or invalid JWT</response>
    /// <response code="403">User is not Admin</response>
    [HttpGet("users")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetUsers(
        [FromQuery] Guid? uid,
        [FromQuery] string? username,
        [FromQuery] string? email,
        [FromQuery] string? phoneNumber,
        [FromQuery] string? details,
        [FromQuery] string? role,
        [FromQuery] bool? isActive,
        [FromQuery] int page,
        [FromQuery] int pageSize)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            Uid = uid,
            Username = username,
            Email = email,
            PhoneNumber = phoneNumber,
            Details = details,
            Role = role,
            IsActive = isActive,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetUsers", parameters);
        logger.Log(LogLevel.Information, "GetUsers by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Retrieves permission records for users (Admin only)
    /// </summary>
    /// <param name="uid">Filter by user ID</param>
    /// <param name="unit">Filter by permission unit type (LevelGroup, Level, Correlation, UserDefinition, Ip&Port, RequestPath)</param>
    /// <param name="permId">Filter by permission ID (for LevelGroup/Level)</param>
    /// <param name="permDetails">Filter by permission details (for Correlation/UserDefinition/Ip&Port/RequestPath)</param>
    /// <param name="page">Page number (default: 1)</param>
    /// <param name="pageSize">Items per page (default: 2500)</param>
    /// <response code="200">Returns JSON array of permissions with user details</response>
    /// <response code="401">Missing or invalid JWT</response>
    /// <response code="403">User is not Admin</response>
    [HttpGet("permissions")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetPermissions(
        [FromQuery] Guid? uid,
        [FromQuery] string? unit,
        [FromQuery] int? permId,
        [FromQuery] string? permDetails,
        [FromQuery] int page,
        [FromQuery] int pageSize)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            CUid = userId,
            Uid = uid,
            Unit = unit,
            PermId = permId,
            PermDetails = permDetails,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetPermissions", parameters);
        logger.Log(LogLevel.Information, "GetPermissions by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Authenticates a user and returns access + refresh tokens
    /// </summary>
    /// <param name="request">Login credentials (Username, Password)</param>
    /// <response code="200">Returns access token and expiration time. Sets refresh token as HTTP‑only cookie.</response>
    /// <response code="401">Invalid username or password</response>
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var saltJson = await service.ExecuteJsonAsync("usp_GetUserSalt", new { request.Username }, def: "{}");
        if (string.IsNullOrEmpty(saltJson) || saltJson == "{}")
            return Unauthorized("Invalid username or password.");
        using var sl = JsonDocument.Parse(saltJson);
        var root = sl.RootElement;
        if (!root.TryGetProperty("UserSalt", out var userSaltObj) || userSaltObj.ValueKind == JsonValueKind.Null)
            return Unauthorized("Invalid username or password.");
        var salt = userSaltObj.GetProperty("Salt").GetString();
        if (string.IsNullOrEmpty(salt))
            return Unauthorized("Invalid username or password.");

        var hashedPassword = HashPasswordWithSalt(request.Password, salt);

        var loginJson = await service.ExecuteJsonAsync("usp_TryLogin", new
        {
            request.Username,
            HashedPassword = hashedPassword
        });

        if (string.IsNullOrWhiteSpace(loginJson))
            return Unauthorized("Invalid username or password.");

        using var doc = JsonDocument.Parse(loginJson);
        var userArray = doc.RootElement.GetProperty("Users");
        if (userArray.GetArrayLength() == 0)
            return Unauthorized();

        var user = userArray[0];
        var uid = user.GetProperty("Uid").GetString();
        var username = user.GetProperty("Username").GetString();
        var role = user.GetProperty("Role").GetString();

        var (accessToken, expiresAt, _) = jwtService.CreateAccessToken(uid!, username!, [role!]);
        var (refreshTokenPlain, refreshTokenEntity) = jwtService.CreateRefreshToken(uid!, GetClientIp());

        await service.ExecuteJsonAsync("usp_SetUserRefreshToken", new
        {
            Uid = uid,
            RefreshToken = refreshTokenEntity.TokenHash,
            ForgeTime = (long)refreshTokenEntity.ExpiresAtUtc.Subtract(DateTime.UtcNow).TotalMilliseconds,
            Ip = GetClientIp()
        });

        Response.Cookies.Append("refreshToken", refreshTokenPlain, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenEntity.ExpiresAtUtc
        });

        logger.Log(LogLevel.Information, "Login by: " + uid);
        return Ok(new { AccessToken = accessToken, ExpiresAt = expiresAt });
    }
    
    /// <summary>
    /// Retrieves system history logs (Admin only)
    /// </summary>
    /// <param name="from">Optional start date filter</param>
    /// <param name="to">Optional end date filter</param>
    /// <param name="page">Page number (default: 1)</param>
    /// <param name="pageSize">Items per page (default: 2500)</param>
    /// <response code="200">Returns JSON array of history entries</response>
    /// <response code="401">Missing or invalid JWT</response>
    /// <response code="403">User is not Admin</response>
    [HttpGet("histories")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetHistories(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] int page,
        [FromQuery] int pageSize)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            CUid = userId,
            From = from,
            To = to,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetHistories", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Creates a new user or updates an existing one (Admin only)
    /// </summary>
    /// <param name="request">User data (Uid optional for update)</param>
    /// <response code="200">Returns operation result as JSON</response>
    /// <response code="401">Missing or invalid JWT</response>
    /// <response code="403">User is not Admin or trying to change another admin</response>
    [HttpPost("upsert-user")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> UpsertUser([FromBody] UpsertUserRequest request)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var salt = request.Password == null ? null : GenerateSalt();
        var hashedPassword = request.Password == null ? null : HashPasswordWithSalt(request.Password!, salt!);

        var parameters = new
        {
            userId,
            request.Uid,
            request.Username,
            request.Email,
            request.PhoneNumber,
            request.Details,
            hashedPassword,
            salt,
            request.Role,
            request.IsActive
        };
        var json = await service.ExecuteJsonAsync("usp_UpsertUser", parameters);
        logger.Log(LogLevel.Information, "Upserted: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Permanently deletes a user (Admin only)
    /// </summary>
    /// <param name="uid">User ID to delete</param>
    /// <response code="200">Returns deleted user ID</response>
    /// <response code="401">Missing or invalid JWT</response>
    /// <response code="403">User is not Admin</response>
    [HttpDelete("delete-user")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteUser([FromQuery] Guid uid)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { CUid = userId, Uid = uid };
        var json = await service.ExecuteJsonAsync("usp_DeleteUser", parameters);
        logger.Log(LogLevel.Information, "Deleted: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Changes password for the authenticated user
    /// </summary>
    /// <param name="request">Old password, new password and username (for salt lookup)</param>
    /// <response code="200">Password successfully changed, old refresh tokens invalidated</response>
    /// <response code="401">Invalid token, or wrong old password, or user not found</response>
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }
        
        var saltJson = await service.ExecuteJsonAsync("usp_GetUserSalt", new { request.Username }, def: "{}");
        if (string.IsNullOrEmpty(saltJson) || saltJson == "{}")
            return Unauthorized("Invalid username or password.");
        using var doc = JsonDocument.Parse(saltJson);
        var root = doc.RootElement;
        if (!root.TryGetProperty("UserSalt", out var userSaltObj) || userSaltObj.ValueKind == JsonValueKind.Null)
            return Unauthorized("Invalid username or password.");
        var salt = userSaltObj.GetProperty("Salt").GetString();
        if (string.IsNullOrEmpty(salt))
            return Unauthorized("Invalid username or password.");
        

        var hashedPassword = HashPasswordWithSalt(request.OldPassword, salt);

        var salt2 = GenerateSalt();
        var hashedPassword2 = HashPasswordWithSalt(request.NewPassword, salt2);

        var parameters = new
        {
            userId,
            hashedPassword,
            hashedPassword2,
            salt2
        };
        var json = await service.ExecuteJsonAsync("usp_ChangePassword", parameters);
        logger.Log(LogLevel.Information, "User Password changed: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Refreshes access token using a valid refresh token
    /// </summary>
    /// <param name="request">User ID (Uid) associated with the refresh token</param>
    /// <response code="200">Returns new access token and expiration. Sets new refresh token cookie.</response>
    /// <response code="401">Invalid or expired refresh token</response>
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken)) return Unauthorized();

        var isValid = await connection.ExecuteScalarAsync<bool>(
            "usp_CheckRefreshTokenValid",
            new { request.Uid, RefreshToken = refreshToken }
        );
        if (!isValid) return Unauthorized();

        var userJson = await service.ExecuteJsonAsync("usp_GetUsers", new { request.Uid });
        using var doc = JsonDocument.Parse(userJson);
        var userArray = doc.RootElement.GetProperty("Users");
        if (userArray.GetArrayLength() == 0)
            return Unauthorized();
        var firstUser = userArray[0];
        var uid = firstUser.GetProperty("Uid").GetString();
        var username = firstUser.GetProperty("Username").GetString();

        var (newAccessToken, expiresAt, _) =
            jwtService.CreateAccessToken(uid!, username!, [firstUser.GetProperty("Role").GetString()!]);

        var (newRefreshTokenPlain, newRefreshTokenEntity) = jwtService.CreateRefreshToken(uid!, GetClientIp());
        await service.ExecuteJsonAsync("usp_SetUserRefreshToken", new
        {
            request.Uid,
            RefreshToken = newRefreshTokenEntity.TokenHash,
            ForgeTime = (long)newRefreshTokenEntity.ExpiresAtUtc.Subtract(DateTime.UtcNow).TotalMilliseconds,
            Ip = GetClientIp()
        });
        Response.Cookies.Append("refreshToken", newRefreshTokenPlain,
            new CookieOptions { HttpOnly = true, Secure = true, Expires = newRefreshTokenEntity.ExpiresAtUtc });
        logger.Log(LogLevel.Information, "Token Refreshed: " + request.Uid);
        return Ok(new { AccessToken = newAccessToken, ExpiresAt = expiresAt });
    }

    /// <summary>
    /// Deactivates a user (sets IsActive = false) and invalidates their refresh tokens (Admin only)
    /// </summary>
    /// <param name="request">User ID to deactivate</param>
    /// <response code="200">User deactivated successfully</response>
    /// <response code="401">Missing or invalid JWT</response>
    /// <response code="403">User is not Admin</response>
    [HttpPost("deactivate-user")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeActiveUser([FromBody] DeActiveUserRequest request)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { userId, request.Uid };
        var json = await service.ExecuteJsonAsync("usp_DeActiveUser", parameters);
        logger.Log(LogLevel.Information, "User Deactivated: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Adds a permission entry to a user (Admin only)
    /// </summary>
    /// <param name="request">Target user ID, unit type, and either PermId or PermDetails</param>
    /// <response code="200">Permission added (or already existed)</response>
    [HttpPost("add-permission")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AddUserPermission([FromBody] AddPermissionRequest request)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            userId,
            request.Uid,
            request.Unit,
            request.PermId,
            request.PermDetails
        };
        var json = await service.ExecuteJsonAsync("usp_AddUserPermission", parameters);
        logger.Log(LogLevel.Information, "User Permission Changed by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Removes a specific permission from a user (Admin only)
    /// </summary>
    /// <param name="uid">Target user ID</param>
    /// <param name="unit">Permission unit</param>
    /// <param name="permId">Permission ID (for LevelGroup/Level)</param>
    /// <param name="permDetails">Permission details (for other unit types)</param>
    /// <response code="200">Permission removed if existed</response>
    [HttpDelete("remove-permission")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RemoveUserPermission([FromQuery] Guid uid,
        [FromQuery] string unit, [FromQuery] int? permId, [FromQuery] string? permDetails)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            userId,
            Uid = uid,
            Unit = unit,
            PermId = permId,
            PermDetails = permDetails
        };
        var json = await service.ExecuteJsonAsync("usp_RemoveUserPermission", parameters);
        logger.Log(LogLevel.Information, "User Permission Changed by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Clears old history entries (Admin only)
    /// </summary>
    /// <param name="from">Delete records older than this date</param>
    /// <response code="200">History cleared successfully</response>
    [HttpDelete("clear-old-histories")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> ClearOldHistories([FromQuery] DateTime from)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { userId, From = from };
        var json = await service.ExecuteJsonAsync("usp_ClearOldHistories", parameters);
        logger.Log(LogLevel.Information, "History was cleared since: " + from);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Logs out the current user – invalidates refresh token and clears cookie
    /// </summary>
    /// <response code="200">Logged out successfully</response>
    /// <response code="401">Invalid or missing token</response>
    [HttpPost("logout")]
    [Authorize] 
    public async Task<IActionResult> Logout()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        await service.ExecuteJsonAsync("usp_SetUserRefreshToken", new
        {
            Uid = userId,
            RefreshToken = (string?)null
        });

        Response.Cookies.Delete("refreshToken");
        return Ok();
    }

    private string GetClientIp()
    {
        var ip = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (string.IsNullOrEmpty(ip))
            ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        return ip ?? "0.0.0.0";
    }

    private string GenerateSalt()
    {
        byte[] saltBytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }
        return Convert.ToBase64String(saltBytes);
    }


}