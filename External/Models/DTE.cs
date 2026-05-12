namespace External.Models;

public class UpsertUserRequest
{
    public Guid? Uid { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Details { get; set; }
    public string? Password { get; set; }
    public string? Role { get; set; }
    public bool IsActive { get; set; } = true;
}

public class ChangePasswordRequest
{
    public string Username { get; set; } = null!;
    public string OldPassword { get; set; } = null!;
    public string NewPassword { get; set; } = null!;
}

public class DeActiveUserRequest
{
    public Guid? Uid { get; set; }
}

public class AddPermissionRequest
{
    public Guid? Uid { get; set; }
    public string Unit { get; set; } = null!;
    public int? PermId { get; set; }
    public string? PermDetails { get; set; }
}

public class UpsertGroupRequest
{
    public int? LevelGroupId { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? ColorCode { get; set; }
    public int? RetentionDays { get; set; }
}

public class UpsertLevelRequest
{
    public int? LevelId { get; set; }
    public int? LevelGroupId { get; set; }
    public string? Name { get; set; }
    public int? SeverityNumber { get; set; }
    public string? ColorCode { get; set; }
    public string? NotifyRole { get; set; }
    public string? Description { get; set; }
}

public class UpsertSourceRequest
{
    public int? SourceId { get; set; }
    public string? Name { get; set; }
    public string? HostName { get; set; }
    public string? Environment { get; set; }
    public string? Zone { get; set; }
    public string? ClientIp { get; set; }
    public string? ClientPort { get; set; }
    public string? TeamOwner { get; set; }
    public string? WebHookUrl { get; set; }
    public bool IsActive { get; set; } = true;
}


public class PivotRequest
{
    public DateTime Per { get; set; }
    public string Unit { get; set; } = null!;
    public string Which { get; set; } = null!;
    public string Values { get; set; } = null!;
}

public class LoginRequest
{
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
}

public class RefreshRequest
{
    public Guid? Uid { get; set; } = null!;
}
