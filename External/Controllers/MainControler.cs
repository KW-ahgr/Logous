using System.Security.Claims;
using External.Models;
using External.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace External.Controllers;

[ApiController]
[Route("api/")]
public class MainController(ILogService service, ILogger<MainController> logger) : ControllerBase
{

    /// <summary>
    /// Searches logs with advanced filtering and pagination
    /// </summary>
    /// <param name="logId">Exact LogId</param>
    /// <param name="levelId">Filter by LevelId</param>
    /// <param name="groupId">Filter by LevelGroupId</param>
    /// <param name="timestampFrom">Start of timestamp range</param>
    /// <param name="timestampTo">End of timestamp range</param>
    /// <param name="receivedAtFrom">Start of received time range</param>
    /// <param name="receivedAtTo">End of received time range</param>
    /// <param name="message">Full‑text search in Message</param>
    /// <param name="correlationId">Exact CorrelationId</param>
    /// <param name="properties">Full‑text search inside PropertiesJson</param>
    /// <param name="userDefinition">Full‑text search in UserDefinition</param>
    /// <param name="clientIp">Exact client IP</param>
    /// <param name="clientPort">Exact client port</param>
    /// <param name="requestPath">Full‑text search in RequestPath</param>
    /// <param name="protocol">Exact protocol (UDP/TCP/RabbitMQ/Kafka)</param>
    /// <param name="sourceId">Filter by SourceId (checks IP/Port permissions)</param>
    /// <param name="page">Page number</param>
    /// <param name="pageSize">Items per page (max 10000)</param>
    /// <param name="withLevels">If true, includes Level and LevelGroup names/colors</param>
    /// <response code="200">Returns JSON array of logs (root: 'Logs')</response>
    /// <response code="401">Missing or invalid JWT</response>
    [HttpGet("logs")]
    [Authorize]
    public async Task<IActionResult> GetLogs(
        [FromQuery] long? logId,
        [FromQuery] int? levelId,
        [FromQuery] int? groupId,
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo,
        [FromQuery] string? message,
        [FromQuery] string? correlationId,
        [FromQuery] string? properties,
        [FromQuery] string? userDefinition,
        [FromQuery] string? clientIp,
        [FromQuery] string? clientPort,
        [FromQuery] string? requestPath,
        [FromQuery] string? protocol,
        [FromQuery] int? sourceId,
        [FromQuery] int page,
        [FromQuery] int pageSize,
        [FromQuery] bool withLevels)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            Uid = userId,
            LogId = logId,
            LevelId = levelId,
            GroupId = groupId,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo,
            Message = message ?? "",
            CorrelationId = correlationId ?? "",
            Properties = properties ?? "",
            UserDefinition = userDefinition ?? "",
            ClientIp = clientIp ?? "",
            ClientPort = clientPort ?? "",
            RequestPath = requestPath ?? "",
            Protocol = protocol ?? "",
            SourceId = sourceId,
            Page = page,
            PageSize = pageSize,
            WithLevels = withLevels
        };
        var json = await service.ExecuteJsonAsync("usp_GetLogs", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Retrieves LevelGroup list with permission filtering
    /// </summary>
    [HttpGet("groups")]
    [Authorize]
    public async Task<IActionResult> GetGroups(
        [FromQuery] int? levelGroupId,
        [FromQuery] string? name,
        [FromQuery] string? colorCode,
        [FromQuery] int? retentionDaysFrom,
        [FromQuery] int? retentionDaysTo,
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
            Uid = userId,
            LevelGroupId = levelGroupId,
            Name = name,
            ColorCode = colorCode,
            RetentionDaysFrom = retentionDaysFrom,
            RetentionDaysTo = retentionDaysTo,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetGroups", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Retrieves Level list with permission filtering (checks LevelGroup and Level permissions)
    /// </summary>
    [HttpGet("levels")]
    [Authorize]
    public async Task<IActionResult> GetLevels(
        [FromQuery] int? levelId,
        [FromQuery] int? levelGroupId,
        [FromQuery] string? name,
        [FromQuery] int? severityNumberFrom,
        [FromQuery] int? severityNumberTo,
        [FromQuery] string? colorCode,
        [FromQuery] string? notifyRole,
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
            Uid = userId,
            LevelId = levelId,
            LevelGroupId = levelGroupId,
            Name = name,
            SeverityNumberFrom = severityNumberFrom,
            SeverityNumberTo = severityNumberTo,
            ColorCode = colorCode,
            NotifyRole = notifyRole,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetLevels", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Retrieves Source list with Full‑Text search and IP/Port permission filtering
    /// </summary>
    [HttpGet("sources")]
    [Authorize]
    public async Task<IActionResult> GetSources(
        [FromQuery] int? sourceId,
        [FromQuery] string? name,
        [FromQuery] string? hostName,
        [FromQuery] string? environment,
        [FromQuery] string? zone,
        [FromQuery] string? clientIp,
        [FromQuery] string? clientPort,
        [FromQuery] string? teamOwner,
        [FromQuery] string? webHookUrl,
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
            Uid = userId,
            SourceId = sourceId,
            Name = name,
            HostName = hostName,
            Environment = environment,
            Zone = zone,
            ClientIp = clientIp,
            ClientPort = clientPort,
            TeamOwner = teamOwner,
            WebHookUrl = webHookUrl,
            IsActive = isActive,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetSources", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Retrieves logs that have no known Level or no matching Source (unknown origin)
    /// </summary>
    [HttpGet("unknowns")]
    [Authorize]
    public async Task<IActionResult> GetUnknownLogs(
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo,
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
            Uid = userId,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetUnknownLogs", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Creates a dynamic pivot table for log counts over different time units
    /// </summary>
    /// <param name="request">Contains Per (reference date), Unit (Hour/Day/Week/Month/Year/All), Which (field to group), Values (comma‑separated)</param>
    /// <response code="200">Returns pivot table as JSON</response>
    [HttpPost("pivot")]
    [Authorize]
    public async Task<IActionResult> CreatePivot([FromBody] PivotRequest request)
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
            request.Per,
            request.Unit,
            request.Which,
            request.Values
        };
        var json = await service.ExecuteJsonAsync("usp_CreatePivot", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Detects sequences of consecutive logs matching specified criteria (e.g., repeated errors)
    /// </summary>
    [HttpGet("sequences")]
    [Authorize]
    public async Task<IActionResult> GetLogsForSequences(
        [FromQuery] int? seriCount,
        [FromQuery] int? levelId,
        [FromQuery] int? groupId,
        [FromQuery] string? message,
        [FromQuery] string? correlationId,
        [FromQuery] string? property,
        [FromQuery] int? forLevelId,
        [FromQuery] int? forGroupId,
        [FromQuery] string? forClientIp,
        [FromQuery] string? forClientPort,
        [FromQuery] string? forRequestPath,
        [FromQuery] string? forProtocol,
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            Uid = userId,
            SeriCount = seriCount,
            LevelId = levelId,
            GroupId = groupId,
            Message = message,
            CorrelationId = correlationId,
            Property = property,
            ForLevelId = forLevelId,
            ForGroupId = forGroupId,
            ForClientIp = forClientIp,
            ForClientPort = forClientPort,
            ForRequestPath = forRequestPath,
            ForProtocol = forProtocol,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo
        };
        var json = await service.ExecuteJsonAsync("usp_GetLogsForSequences", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Returns alternative log entries and traces of similar logs (uses LAG/LEAD)
    /// </summary>
    [HttpGet("alternatives")]
    [Authorize]
    public async Task<IActionResult> GetAlternatives(
        [FromQuery] int? levelId,
        [FromQuery] int? groupId,
        [FromQuery] string? message,
        [FromQuery] string? correlationId,
        [FromQuery] string? property,
        [FromQuery] string? userDefinition,
        [FromQuery] string? clientIp,
        [FromQuery] string? clientPort,
        [FromQuery] string? requestPath,
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            Uid = userId,
            LevelId = levelId,
            GroupId = groupId,
            Message = message,
            CorrelationId = correlationId,
            Property = property,
            UserDefinition = userDefinition,
            ClientIp = clientIp,
            ClientPort = clientPort,
            RequestPath = requestPath,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo
        };
        var json = await service.ExecuteJsonAsync("usp_AlternativeLogs", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Ranks logs by count of selected dimensions (Groups, Levels, Sources, etc.)
    /// </summary>
    [HttpGet("rank")]
    [Authorize]
    public async Task<IActionResult> GetRankings(
        [FromQuery] bool? groups,
        [FromQuery] bool? levels,
        [FromQuery] bool? sources,
        [FromQuery] bool? messages,
        [FromQuery] bool? correlationIds,
        [FromQuery] bool? clientIps,
        [FromQuery] bool? requestPaths,
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo,
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
            Uid = userId,
            Groups = groups == true ? 1 : 0,
            Levels = levels == true ? 1 : 0,
            Sources = sources == true ? 1 : 0,
            Messages = messages == true ? 1 : 0,
            CorrelationIds = correlationIds == true ? 1 : 0,
            ClientIps = clientIps == true ? 1 : 0,
            RequestPaths = requestPaths == true ? 1 : 0,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_RankLogs", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Lists logs whose delivery delay exceeds a threshold (ReceivedAt - Timestamp)
    /// </summary>
    [HttpGet("delayed")]
    [Authorize]
    public async Task<IActionResult> GetDelayedLogs(
        [FromQuery] int? delaysInMilliseconds,
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo,
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
            Uid = userId,
            DelaysInMilliseconds = delaysInMilliseconds,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo,
            Page = page,
            PageSize = pageSize
        };
        var json = await service.ExecuteJsonAsync("usp_GetDelayedLogs", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Returns items (groups, levels, sources, etc.) that have fewer logs than the specified minimum count
    /// </summary>
    [HttpGet("less")]
    [Authorize]
    public async Task<IActionResult> GetThingsWithLessLog(
        [FromQuery] bool? groups,
        [FromQuery] bool? levels,
        [FromQuery] bool? sources,
        [FromQuery] bool? messages,
        [FromQuery] bool? correlationIds,
        [FromQuery] bool? clientIps,
        [FromQuery] bool? requestPaths,
        [FromQuery] int? minCount,
        [FromQuery] DateTime? timestampFrom,
        [FromQuery] DateTime? timestampTo,
        [FromQuery] DateTime? receivedAtFrom,
        [FromQuery] DateTime? receivedAtTo)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new
        {
            Uid = userId,
            Groups = groups == true ? 1 : 0,
            Levels = levels == true ? 1 : 0,
            Sources = sources == true ? 1 : 0,
            Messages = messages == true ? 1 : 0,
            CorrelationIds = correlationIds == true ? 1 : 0,
            ClientIps = clientIps == true ? 1 : 0,
            RequestPaths = requestPaths == true ? 1 : 0,
            MinCount = minCount,
            TimestampFrom = timestampFrom,
            TimestampTo = timestampTo,
            ReceivedAtFrom = receivedAtFrom,
            ReceivedAtTo = receivedAtTo
        };
        var json = await service.ExecuteJsonAsync("usp_GetThingsWithLessLog", parameters);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Creates or updates a LevelGroup (Admin only)
    /// </summary>
    [HttpPost("upsert-group")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> UpsertGroup([FromBody] UpsertGroupRequest request)
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
            request.LevelGroupId,
            request.Name,
            request.Description,
            request.ColorCode,
            request.RetentionDays
        };
        var json = await service.ExecuteJsonAsync("usp_UpsertGroup", parameters);
        logger.Log(LogLevel.Information, "Group was upserted by: " + userId);
        return Content(json, "application/json");
    }
    
    /// <summary>
    /// Deletes a LevelGroup (Admin only)
    /// </summary>
    [HttpDelete("delete-group")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteGroup([FromQuery] int levelGroupId)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { userId, LevelGroupId = levelGroupId };
        var json = await service.ExecuteJsonAsync("usp_DeleteGroup", parameters);
        logger.Log(LogLevel.Information, "Group was deleted by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Creates or updates a Level (Admin only)
    /// </summary>
    [HttpPost("upsert-level")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> UpsertLevel([FromBody] UpsertLevelRequest request)
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
            request.LevelId,
            request.LevelGroupId,
            request.Name,
            request.SeverityNumber,
            request.ColorCode,
            request.NotifyRole,
            request.Description
        };
        var json = await service.ExecuteJsonAsync("usp_UpsertLevel", parameters);
        logger.Log(LogLevel.Information, "Level was Upserted by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Deletes a Level (Admin only)
    /// </summary>
    [HttpDelete("delete-level")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteLevel([FromQuery] int levelId)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { userId, LevelId = levelId };
        var json = await service.ExecuteJsonAsync("usp_DeleteLevel", parameters);
        logger.Log(LogLevel.Information, "Level was deleted by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Creates or updates a Source (Admin only)
    /// </summary>
    [HttpPost("upsert-source")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> UpsertSource([FromBody] UpsertSourceRequest request)
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
            request.SourceId,
            request.Name,
            request.HostName,
            request.Environment,
            request.Zone,
            request.ClientIp,
            request.ClientPort,
            request.TeamOwner,
            request.WebHookUrl,
            request.IsActive
        };
        var json = await service.ExecuteJsonAsync("usp_UpsertSource", parameters);
        logger.Log(LogLevel.Information, "Source was upserted by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Deletes a Source (Admin only)
    /// </summary>
    [HttpDelete("delete-source")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteSource([FromQuery] int sourceId)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { userId, SourceId = sourceId };
        var json = await service.ExecuteJsonAsync("usp_DeleteSource", parameters);
        logger.Log(LogLevel.Information, "Source was deleted by: " + userId);
        return Content(json, "application/json");
    }

    /// <summary>
    /// Deletes logs older than the given date (Admin only)
    /// </summary>
    [HttpDelete("clear-old-logs")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> ClearOldLogs([FromQuery] DateTime from)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            logger.Log(LogLevel.Critical, "Bad Request!   " + GetClientIp());
            return Unauthorized("Invalid token.");
        }

        var parameters = new { userId, From = from };
        var json = await service.ExecuteJsonAsync("usp_ClearOldLogs", parameters);
        logger.Log(LogLevel.Information, "Logs where be cleared since: " + from);
        return Content(json, "application/json");
    }

    private string GetClientIp()
    {
        var ip = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (string.IsNullOrEmpty(ip))
            ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        return ip ?? "0.0.0.0";
    }

}