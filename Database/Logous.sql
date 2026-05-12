create database LogousDB;
go;
use LogousDB;
go;

-----------------------------------------------------------------------------------------

create table [User] (
    Uid uniqueidentifier primary key nonclustered default newid(),
    Username nvarchar(100) not null unique,
    Email nvarchar(256),
    PhoneNumber nvarchar(25),
    Details nvarchar(375),
    HashedPassword nvarchar(max) not null,
    Salt nvarchar(65) not null,
    Role nvarchar(9) not null default 'Viewer' check (Role in ('Viewer', 'Admin', 'Auditor')),
    IsActive bit not null default 1,
    CreatedAt datetime2(3) not null default getutcdate(),
    LastLoginAt datetime2(7),
    LastPasswordChanged datetime2(7),
    RefreshToken nvarchar(max),
    RefreshTokenCreatedAt datetime2(7),
    RefreshTokenExpiredAt datetime2(7),
    RefreshTokenCreatedByIp nvarchar(32),
    index ix_User_CreatedAt clustered (CreatedAt)
);

create table [Permission] (
    PermId int primary key identity,
    Uid uniqueidentifier not null foreign key references [User](Uid) on delete cascade,
    Unit nvarchar(18) not null check (Unit in ('LevelGroup', 'Level', 'Correlation', 'UserDefinition', 'Ip&Port', 'RequestPath')),
    PermedId int,
    PermedDetails nvarchar(500),
    check (PermId is not null or PermedDetails is not null),
    index ix_Permission_Uid (Uid),
    index ix_Permission_Permed (PermedId, PermedDetails),
    unique (Uid, Unit, PermId, PermedDetails)
);

create table History (
    Hid bigint primary key identity,
    Uid uniqueidentifier not null,
    Operation nvarchar(300) not null,
    At datetime2(7) not null default getutcdate()
);

create table LevelGroup (
    LevelGroupId   int primary key identity,
    Name           nvarchar(100) not null unique,
    Description    nvarchar(500) null,
    ColorCode      nvarchar(7) default '#FF0000',
    RetentionDays  int default 30
);

create table Level (
    LevelId        int primary key identity,
    LevelGroupId   int foreign key references LevelGroup(LevelGroupId) on delete cascade,
    Name           nvarchar(50) not null,
    SeverityNumber int not null default 10,
    ColorCode      nvarchar(7) default '#FF0000',
    NotifyRole     nvarchar(50) null,
    Description    nvarchar(200) null,
    CreatedAt      datetime2 default getutcdate(),
    UpdatedAt      datetime2 null
);

create table Source (
    SourceId       int identity,
    Name           nvarchar(255) not null unique,
    HostName       nvarchar(255) null,
    Environment    nvarchar(50) null,
    Zone           nvarchar(65) null,
    ClientIp       nvarchar(45) null,
    ClientPort     nvarchar(6) null,
    TeamOwner      nvarchar(100) null,
    WebhookUrl     nvarchar(500) null,
    IsActive       bit not null default 1,
    constraint pk_SourceId primary key (SourceId),
    unique (ClientIp, ClientPort)
);

create table Log (
    LogId          bigint identity,
    LevelId        int null foreign key references Level(LevelId) on delete set null,
    [Timestamp]    datetime2(7) not null,
    ReceivedAt     datetime2 default getutcdate(),
    [Message]      nvarchar(max) not null,
    CorrelationId  nvarchar(100) null,
    PropertiesJson nvarchar(max) null,
    UserDefinition nvarchar(150) null,
    ClientIp       nvarchar(45) not null,
    ClientPort     nvarchar(6) null,
    RequestPath    nvarchar(500) null,
    Protocol       nvarchar(20) default 'Unknown',
    constraint pk_LogId primary key (LogId),
    index ix_Log_Timestamp ([Timestamp]),
    index ix_Log_CorrelationId (CorrelationId),
    index ix_Log_Timestamp_LevelId ([Timestamp], LevelId)
);
go;

create fulltext catalog ft_Logs as default;
create fulltext index on Log(Message, PropertiesJson, UserDefinition, RequestPath)
    key index pk_LogId
    with stoplist = system ;
create fulltext index on Source(Name, HostName, Environment, Zone, WebhookUrl, ClientIp, ClientPort)
    key index pk_SourceId
    with stoplist = system ;
go;

-----------------------------------------------------------------------------------------

create procedure usp_UpsertUser (
    @CUid uniqueidentifier = null,
    @Uid uniqueidentifier = null,
    @Username nvarchar(100) = null,
    @Email nvarchar(256) = null,
    @PhoneNumber nvarchar(25) = null,
    @Details nvarchar(375) = null,
    @HashedPassword nvarchar(max) = null,
    @Salt nvarchar(65) = null,
    @Role nvarchar(9) = null,
    @IsActive bit = 1
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;

    merge into [User] as u
    using (values (@Uid)) as r(Uid)
    on u.Uid = r.Uid
    when matched then
        update
        set Username = coalesce(@Username, Username),
            Email = coalesce(@Email, Email),
            PhoneNumber = coalesce(@PhoneNumber, PhoneNumber),
            Details = coalesce(@Details, Details),
            HashedPassword = coalesce(@HashedPassword, HashedPassword),
            Salt = coalesce(@Salt, Salt),
            Role = coalesce(@Role, Role),
            IsActive = coalesce(@IsActive, IsActive)
    when not matched then
        insert (Username, Email, PhoneNumber, Details, HashedPassword, Salt, Role, IsActive)
        values (@Username, @Email, @PhoneNumber, @Details, @HashedPassword, @Salt, @Role, @IsActive)
    output $action, inserted.Uid;

    if @@rowcount > 0
    begin
        if @Uid is not null
            insert into History  (Uid, Operation)
            values (@Uid, 'User Updated');
        else
            insert into History  (Uid, Operation)
            values (scope_identity(), 'User Added');
    end

end
go;

create procedure usp_DeleteUser (
    @CUid uniqueidentifier = null,
    @Uid uniqueidentifier = null
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;

    delete from [User] where Uid = @Uid;

    if @@rowcount > 0
        insert into History  (Uid, Operation)
        values (@Uid, 'User Deleted');
end
go;

create procedure usp_ChangePassword (
    @Uid uniqueidentifier = null,
    @OldPassword nvarchar(max),
    @NewPassword nvarchar(max),
    @NewSalt nvarchar(65)
) as
begin
    update [User] set HashedPassword = @NewPassword, Salt = @NewSalt where HashedPassword = @OldPassword and IsActive = 1 and Uid = @Uid;

    if @@rowcount > 0
    begin
        insert into History  (Uid, Operation)
        values (@Uid, 'User Updated');

        exec usp_SetUserRefreshToken @Uid = @Uid;
    end
end
go;

create procedure usp_SetUserRefreshToken (
    @Uid uniqueidentifier = null,
    @RefreshToken nvarchar(max) = null,
    @ForgeTime bigint = null,
    @Ip nvarchar(32) = null
) as
begin
    if @RefreshToken is null
    begin
        update [User]
        set RefreshToken = null,
            RefreshTokenCreatedAt = null,
            RefreshTokenExpiredAt = null,
            RefreshTokenCreatedByIp = null
        where @Uid = Uid and @Uid is not null;
        return;
    end
    update [User]
    set RefreshToken = @RefreshToken,
        RefreshTokenCreatedAt = getutcdate(),
        RefreshTokenExpiredAt = dateadd(millisecond, isnull(@ForgeTime, 172800099), getutcdate()),
        RefreshTokenCreatedByIp = @Ip
    where @Uid = Uid and @Uid is not null;

    if @@rowcount > 0
        insert into History  (Uid, Operation)
        values (@Uid, 'User Refresh-Token was changed');
end
go;

create procedure usp_CheckRefreshTokenValid (
    @Uid uniqueidentifier = null,
    @RefreshToken nvarchar(max) = null
) as
    select exists (
        select 1 from [User] where @Uid = Uid and @RefreshToken = RefreshToken and RefreshTokenExpiredAt > getutcdate() and [User].IsActive = 1
    )
go;

create procedure usp_DeActiveUser (
    @CUid uniqueidentifier = null,
    @Uid uniqueidentifier = null
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;

    update [User] set IsActive = false where Uid = @Uid;
    exec usp_SetUserRefreshToken @Uid = @Uid;

    if @@rowcount > 0
        insert into History  (Uid, Operation)
        values (@Uid, 'User became inactivated');
end
go;

create procedure usp_AddUserPermission (
    @CUid uniqueidentifier = null,
    @Uid uniqueidentifier = null,
    @Unit nvarchar(18) = null,
    @PermId int = null,
    @PermDetails nvarchar(500) = null
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'User is Admin', 1;

    if @Unit is null   throw 50000, '@Unit are required', 1;
    if @Unit in ('LevelGroup', 'Level')   set @PermDetails = null;
    if @Unit in ('Correlation', 'UserDefinition', 'Ip&Port', 'RequestPath')   set @PermId = null;

    if not exists (
        select 1 from [Permission] p where @Uid = Uid and @Unit = Unit and @PermId = PermId and @PermDetails = PermedDetails
    )  insert into [Permission] values (@Uid, @Unit, @PermId, @PermDetails);

    if scope_identity() > 0
        insert into History  (Uid, Operation)
        values (@Uid, 'Permissions was added for ' + @Unit + ' => ' + isnull(@PermDetails, isnull(try_convert(nvarchar(9), @PermId), '??')));
end
go;

create procedure usp_RemoveUserPermission (
    @CUid uniqueidentifier = null,
    @Uid uniqueidentifier = null,
    @Unit nvarchar(18) = null,
    @PermId int = null,
    @PermDetails nvarchar(500) = null
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'User is Admin', 1;

    delete from [Permission] where @Uid = Uid and @Unit = Unit and @PermId = PermId and @PermDetails = PermedDetails;

    if @@rowcount > 0
        insert into History  (Uid, Operation)
        values (@Uid, 'Permissions was removed for ' + @Unit + ' => ' + isnull(@PermDetails, isnull(try_convert(nvarchar(9), @PermId), '??')));
end
go;

create function ufun_HasUserPermissionLevelGroup (
    @Uid uniqueidentifier = null,
    @LevelGroupId int = null
) returns bit
as
    return exists (
        select 1 from Permission p join [User] u on u.Uid = p.Uid
        where p.Uid = @Uid and u.IsActive and
            (
                (u.Role in ('Admin', 'Auditor')) or
                (@LevelGroupId is not null and p.Unit = 'LevelGroup' and p.PermId = @LevelGroupId) )
    );
go;

create function ufun_HasUserPermissionLevel (
    @Uid uniqueidentifier = null,
    @LevelId int = null
) returns bit
as
begin
    declare @g int = null;
    select @g = LevelGroupId from Level where LevelId = @LevelId;
    return exists (
        select 1 from Permission p join [User] u on u.Uid = p.Uid
        where p.Uid = @Uid and u.IsActive and
            (
                (u.Role in ('Admin', 'Auditor')) or
                (@LevelId is not null and ((p.Unit = 'Level' and  p.PermId = @LevelId) or (p.Unit = 'LevelGroup' and p.PermId = @g))) )
    );
end
go;

create function ufun_HasUserPermissionCorrelation (
    @Uid uniqueidentifier = null,
    @CorrelationId nvarchar(100) = null
) returns bit
as
    return exists (
        select 1 from Permission p join [User] u on u.Uid = p.Uid
        where p.Uid = @Uid and u.IsActive and
            (
                (u.Role in ('Admin', 'Auditor')) or
                (@CorrelationId is not null and p.Unit = 'Correlation' and p.PermedDetails = @CorrelationId) )
    );
go;

create function ufun_HasUserPermissionUserDefinition (
    @Uid uniqueidentifier = null,
    @UserDefinition nvarchar(150) = null
) returns bit
as
    return exists (
        select 1 from Permission p join [User] u on u.Uid = p.Uid
        where p.Uid = @Uid and u.IsActive and
            (
                (u.Role in ('Admin', 'Auditor')) or
                (@UserDefinition is not null and p.Unit = 'UserDefinition' and p.PermedDetails = @UserDefinition) )
    );
go;

create function ufun_HasUserPermissionIpPort (
    @Uid uniqueidentifier = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null
) returns bit
as
    return exists (
        select 1 from Permission p join [User] u on u.Uid = p.Uid
        where p.Uid = @Uid and u.IsActive and
            (
                (u.Role in ('Admin', 'Auditor')) or
                (@ClientIp is not null and p.Unit = 'Ip&Port' and p.PermedDetails = @ClientIp + isnull(':' + @ClientPort, '')) )
    );
go;

create function ufun_HasUserPermissionRequestPath (
    @Uid uniqueidentifier = null,
    @RequestPath nvarchar(500) = null
) returns bit
as
    return exists (
        select 1 from Permission p join [User] u on u.Uid = p.Uid
        where p.Uid = @Uid and u.IsActive and
            (
                (u.Role in ('Admin', 'Auditor')) or
                (@RequestPath is not null and p.Unit = 'RequestPath' and p.PermedDetails = @RequestPath) )
    );
go;

create function ufun_IsAdmin (
    @Uid uniqueidentifier = null
) returns bit
as
    return exists (select 1 from [User] where @Uid = Uid and Role = 'Admin');
go;

create procedure usp_GetUsers (
    @Uid uniqueidentifier = null,
    @Username nvarchar(100) = null,
    @Email nvarchar(256) = null,
    @PhoneNumber nvarchar(25) = null,
    @Details nvarchar(375) = null,
    @Role nvarchar(9) = null,
    @IsActive bit = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    set @Username = isnull(@Username, '');
    set @Email = isnull(@Email, '');
    set @PhoneNumber = isnull(@PhoneNumber, '');
    set @Details = isnull(@Details, '');
    set @Role = isnull(@Role, '');

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select Username,
           Email,
           Details,
           Role,
           IsActive,
           CreatedAt,
           LastLoginAt,
           LastPasswordChanged,
           RefreshTokenCreatedByIp
    from [User]
    where (@Uid is null or @Uid = Uid) and
        (@Username is null or @Username = Username) and
        (@Email is null or @Email = Email) and
        (@PhoneNumber is null or @PhoneNumber = PhoneNumber) and
        (@Details is null or @Details = Details) and
        (@Role is null or @Role = Role) and
        (@IsActive is null or @IsActive = IsActive)
    order by CreatedAt
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('Users');
end
go;

create procedure usp_GetPermissions (
    @CUid uniqueidentifier = null,
    @Uid uniqueidentifier = null,
    @Unit nvarchar(18) = null,
    @PermId int = null,
    @PermDetails nvarchar(500) = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;

    set nocount on;

    set @Unit = isnull(@Unit, '');
    set @PermDetails = isnull(@PermDetails, '');

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select p.*,
           u.Username,
           u.Email,
           u.PhoneNumber,
           u.IsActive
    from Permission as p
    join [User] u on p.Uid = u.Uid
    where (@Uid is null or @Uid = p.Uid) and
          (@Unit is null or @Unit = p.Unit) and
          (@PermId is null or @PermId = p.PermId) and
          (@PermDetails is null or @PermDetails = p.PermedDetails)
    order by p.PermId
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('Permissions');
end
go;

create procedure usp_TryLogin (
    @Username nvarchar(100) = null,
    @HashedPassword nvarchar(max) = null
) as
begin
    declare @Uid uniqueidentifier;

    select @Uid = Uid,
           Uid as 'Uid',
           Username,
           Email,
           Details,
           Role,
           IsActive,
           CreatedAt,
           LastLoginAt,
           LastPasswordChanged,
           RefreshTokenCreatedByIp
    from [User]
    where @Username = Username and @HashedPassword = HashedPassword
    for json path, include_null_values, root('Users');

    if @Uid is not null
        insert into History (Uid, Operation)
        values (@Uid, 'User Loged in');
end
go;

create procedure usp_GetUserSalt (
    @Username nvarchar(100) = null
) as
    select Salt
    from [User]
    where @Username = Username
    for json path, include_null_values, root('UserSalt');
go;

create procedure usp_GetHistories (
    @CUid uniqueidentifier = null,
    @From datetime2(7) = null,
    @To datetime2(7) = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    if ufun_IsAdmin(@CUid) = 0   throw 50000, 'Permission Denied', 1;

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select * from History
    where (@From is null or @From <= At) and
          (@To is null or @To >= At)
    order by At desc
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('SystemHistories');

end
go;

create procedure usp_ClearOldHistories (
    @Uid uniqueidentifier = null,
    @From datetime2(7) = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;
    if @From is null
        begin
            print '@From is empty...';
            return;
        end

    delete from History where At < @From;
end
go;

-----------------------------------------------------------------------------------------

create procedure usp_UpsertGroup (
    @Uid uniqueidentifier = null,
    @LevelGroupId int = null,
    @Name nvarchar(100) = null,
    @Description nvarchar(500) = null,
    @ColorCode nvarchar(7) = null,
    @RetentionDays int = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;

    set nocount on;

    merge into LevelGroup as lg
    using (values (@LevelGroupId)) as r(LevelGroupId)
    on r.LevelGroupId = lg.LevelGroupId
    when matched then
        update
        set Name = @Name, Description = @Description, ColorCode = @ColorCode, RetentionDays = @RetentionDays
    when not matched then
        insert (name, description, colorcode, retentiondays)
        values (@Name, @Description, @ColorCode, @RetentionDays)
    output $action, inserted.LevelGroupId;
end
go;

create procedure usp_UpsertLevel (
    @Uid uniqueidentifier = null,
    @LevelId int = null,
    @LevelGroupId int = null,
    @Name nvarchar(50) = null,
    @SeverityNumber int = null,
    @ColorCode nvarchar(7) = null,
    @NotifyRole nvarchar(50) = null,
    @Description nvarchar(200) = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;

    set nocount on;

    merge into Level as l
    using (values (@LevelId)) as r(LevelId)
    on l.LevelId = r.LevelId
    when matched then
        update
        set LevelGroupId = @LevelGroupId, Name = @Name, SeverityNumber = @SeverityNumber, ColorCode = @ColorCode,
            NotifyRole = @NotifyRole, Description = @Description, UpdatedAt = getutcdate()
    when not matched then
        insert (LevelGroupId, Name, SeverityNumber, ColorCode, NotifyRole, Description)
        values (@LevelGroupId, @Name, @SeverityNumber, @ColorCode, @NotifyRole, @Description)
    output $action, inserted.LevelId;
end
go;

create procedure usp_UpsertSource (
    @Uid uniqueidentifier = null,
    @SourceId int = null,
    @Name nvarchar(255) = null,
    @HostName nvarchar(255) = null,
    @Environment nvarchar(50) = null,
    @Zone nvarchar(65) = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null,
    @TeamOwner nvarchar(100) = null,
    @WebHookUrl nvarchar(500) = null,
    @IsActive bit = 1
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;

    set nocount on;

    merge into Source as s
    using (values (@SourceId)) as r (SourceId)
    on s.SourceId = r.SourceId
    when matched then
        update
        set Name = @Name, HostName = @HostName, Environment = @Environment, Zone = @Zone, ClientIp = @ClientIp,
            ClientPort = @ClientPort, TeamOwner = @TeamOwner, WebhookUrl = @WebHookUrl, IsActive = @IsActive
    when not matched then
        insert (name, hostname, Environment, zone, clientip, clientport, teamowner, webhookurl, IsActive)
        values (@Name, @HostName, @Environment, @Zone, @ClientIp, @ClientPort, @TeamOwner, @WebHookUrl, @IsActive)
    output $action, inserted.SourceId;
end
go;

create procedure usp_AddLog (
    @LevelId int = null,
    @Timestamp datetime2(7) = null,
    @Message nvarchar(max) = null,
    @CorrelationId nvarchar(100) = null,
    @PropertiesJson nvarchar(max) = null,
    @UserDefinition nvarchar(150) = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null,
    @RequestPath nvarchar(500) = null,
    @Protocol nvarchar(20) = null
) as
    insert into Log (LevelId, [Timestamp], [Message], CorrelationId, PropertiesJson, UserDefinition, ClientIp, ClientPort,
                     RequestPath, Protocol)
    values (@LevelId, @Timestamp, @Message, @CorrelationId, @PropertiesJson,
            @UserDefinition, @ClientIp, @ClientPort, @RequestPath,
            @Protocol);
go;

create procedure usp_DeleteGroup(
    @Uid uniqueidentifier = null,
    @LevelGroupId int = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;

    delete from LevelGroup
--     output deleted.*
    where LevelGroupId = @LevelGroupId;
end
go;

create procedure usp_DeleteLevel(
    @Uid uniqueidentifier = null,
    @LevelId int = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;

    delete from Level
--     output deleted.*
    where LevelId = @LevelId;
end
go;

create procedure usp_DeleteSource(
    @Uid uniqueidentifier = null,
    @SourceId int = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;

    delete from Source
--     output deleted.*
    where SourceId = @SourceId;
end
go;

create procedure usp_GetGroups (
    @Uid uniqueidentifier = null,
    @LevelGroupId int = null,
    @Name nvarchar(100) = null,
    @ColorCode nvarchar(7) = null,
    @RetentionDaysFrom int = null,
    @RetentionDaysTo int = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    set @Name = isnull(@Name, '');
    set @ColorCode = isnull(@ColorCode, '');

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select * from LevelGroup lv
    where (@LevelGroupId is null or LevelGroupId = @LevelGroupId) and
          (@Name = '' or Name = @Name) and
          (@ColorCode = '' or ColorCode = @ColorCode) and
          (@RetentionDaysFrom is null or RetentionDays >= @RetentionDaysFrom) and
          (@RetentionDaysTo is null or RetentionDays <= @RetentionDaysTo) and
          ufun_HasUserPermissionLevelGroup (@Uid, LevelGroupId)
    order by Name, LevelGroupId
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('LevelGroups');
end
go;

create procedure usp_GetLevels (
    @Uid uniqueidentifier = null,
    @LevelId int = null,
    @LevelGroupId int = null,
    @Name nvarchar(50) = null,
    @SeverityNumberFrom int = null,
    @SeverityNumberTo int = null,
    @ColorCode nvarchar(7) = null,
    @NotifyRole nvarchar(50) = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    set @Name = isnull(@name, '');
    set @ColorCode = isnull(@ColorCode, '');
    set @NotifyRole = isnull(@NotifyRole, '');

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select * from Level
    where (@LevelId is null or LevelId = @LevelId) and
          (@LevelGroupId is null or LevelGroupId = @LevelGroupId) and
          (@Name = '' or Name = @Name) and
          (@SeverityNumberFrom is null or SeverityNumber >= @SeverityNumberFrom) and
          (@SeverityNumberTo is null or SeverityNumber <= @SeverityNumberTo) and
          (@ColorCode = '' or ColorCode = @ColorCode) and
          (@NotifyRole = '' or NotifyRole = @NotifyRole) and
          (ufun_HasUserPermissionLevelGroup (@Uid, LevelGroupId) or
           ufun_HasUserPermissionLevel (@Uid, LevelId))
    order by Name, LevelGroupId, LevelId
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('Levels');
end
go;

create procedure usp_GetSources (
    @Uid uniqueidentifier = null,
    @SourceId int = null,
    @Name nvarchar(255) = null,
    @HostName nvarchar(255) = null,
    @Environment nvarchar(50) = null,
    @Zone nvarchar(65) = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null,
    @TeamOwner nvarchar(100) = null,
    @WebHookUrl nvarchar(500) = null,
    @IsActive bit = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    set @Name = isnull(@Name, '');
    set @HostName = isnull(@HostName, '');
    set @Environment = isnull(@Environment, '');
    set @Zone = isnull(@Zone, '');
    set @ClientIp = isnull(@ClientIp, '');
    set @ClientPort = isnull(@ClientPort, '');
    set @TeamOwner = isnull(@TeamOwner, '');
    set @WebHookUrl = isnull(@WebHookUrl, '');

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select * from Source
    where (@SourceId is null or SourceId = @SourceId) and
          (@Name = '' or contains (Name, @Name)) and
          (@HostName = '' or contains (HostName, @HostName)) and
          (@Environment = '' or contains (Environment, @Environment)) and
          (@Zone = '' or contains (Zone, @Zone)) and
          (@ClientIp = '' or contains (ClientIp, @ClientIp)) and
          (@ClientPort = '' or contains (ClientPort, @ClientPort)) and
          (@TeamOwner = '' or contains (TeamOwner, @TeamOwner)) and
          (@WebHookUrl = '' or contains (WebHookUrl, @WebHookUrl)) and
          (@IsActive is null or IsActive = @IsActive) and
          ufun_HasUserPermissionIpPort(@Uid, ClientIp, ClientPort)
    order by Name, Zone, Environment, HostName, WebhookUrl, SourceId
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('Sources');
end
go;

-- gets filtered result
create procedure usp_GetLogs (
    @Uid uniqueidentifier = null,
    @LogId bigint = null,
    @LevelId int = null,
    @GroupId int = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null,
    @Message nvarchar(max) = null,
    @CorrelationId nvarchar(100) = null,
    @Properties nvarchar(max) = null,
    @UserDefinition nvarchar(150) = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null,
    @RequestPath nvarchar(500) = null,
    @Protocol nvarchar(20) = null,
    @SourceId int = null,
    @Page int = null,
    @PageSize int = null,
    @WithLevels bit = 0
) as
begin
    set nocount on;

    set @Message = isnull(@Message, '');
    set @CorrelationId = isnull(@CorrelationId, '');
    set @Properties = isnull(@Properties, '');
    set @UserDefinition = isnull(@UserDefinition, '');
    set @ClientIp = isnull(@ClientIp, '');
    set @ClientPort = isnull(@ClientPort, '');
    set @RequestPath = isnull(@RequestPath, '');
    set @Protocol = isnull(@Protocol, '');

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    declare @Sources table (address nvarchar(52));
    if @SourceId is not null
        insert into @Sources select isnull(ClientIp, '') + isnull(ClientPort, '')
         from Source
         where SourceId = @SourceId and
               ufun_HasUserPermissionIpPort (@Uid, ClientIp, ClientPort);

    if @WithLevels = 1
    begin
        select l.LogId as LogId,
               l.LevelId as level_id,
               l.[Timestamp] as timestamp,
               l.ReceivedAt as receivedAt,
               l.[Message] as message,
               l.CorrelationId as correlationId,
               l.PropertiesJson as propertiesAsJson,
               l.UserDefinition as userDefinition,
               l.ClientIp as clientIp,
               l.ClientPort as clientPort,
               l.RequestPath as requestPath,
               l.Protocol as protocol,
               v.Name as level_name,
               v.ColorCode as level_color,
               v.NotifyRole as notifyRole,
               v.SeverityNumber as severityNumber,
               lg.Name as group_name,
               lg.ColorCode as group_color
        from Log l
        left join Level v on v.LevelId = l.LevelId
        left join LevelGroup lg on v.LevelGroupId = lg.LevelGroupId
        where (@LogId is null or l.LogId = @LogId) and
            (@LevelId is null or l.LevelId = @LevelId) and
            (@GroupId is null or v.LevelGroupId = @GroupId) and
            (@TimestampFrom is null or l.[timestamp] >= @TimestampFrom) and
            (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
            (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
            (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
            (@Message = '' or contains(l.[Message], @Message)) and
            (@CorrelationId = '' or l.CorrelationId = @CorrelationId) and
            (@Properties = '' or contains (l.PropertiesJson, @Properties)) and
            (@UserDefinition = '' or contains (l.UserDefinition, @UserDefinition)) and
            (@ClientIp = '' or l.ClientIp = @ClientIp) and
            (@ClientPort = '' or l.ClientPort = @ClientPort) and
            (@RequestPath = '' or l.RequestPath = @RequestPath) and
            (@Protocol = '' or l.Protocol = @Protocol) and
            (@SourceId is null or l.ClientIp + isnull(l.ClientPort, '') in (select address from @Sources)) and
            (
                ufun_HasUserPermissionLevelGroup (@Uid, v.LevelGroupId) or
                ufun_HasUserPermissionLevel(@Uid, l.LevelId) or
                ufun_HasUserPermissionIpPort(@Uid, l.ClientIp, l.ClientPort) or
                ufun_HasUserPermissionCorrelation(@Uid, l.CorrelationId) or
                ufun_HasUserPermissionUserDefinition(@Uid, l.UserDefinition) or
                ufun_HasUserPermissionRequestPath(@Uid, l.RequestPath)
                )
        order by l.Timestamp desc
        offset @Off rows
        fetch next @PageSize rows only
        for json path, include_null_values, root('Logs');
    end

    else
    begin
        create table #GroupLevels (Gid int unique nonclustered) with (memory_optimized = on);
        if @GroupId is not null
            insert into #GroupLevels
            select LevelId from Level
            where LevelGroupId = @GroupId and
            ufun_HasUserPermissionLevelGroup (@Uid, LevelGroupId);

        select LogId as LogId,
               LevelId as level_id,
               [Timestamp] as timestamp,
               ReceivedAt as receivedAt,
               [Message] as message,
               CorrelationId as correlationId,
               PropertiesJson as propertiesAsJson,
               UserDefinition as userDefinition,
               ClientIp as clientIp,
               ClientPort as clientPort,
               RequestPath as requestPath,
               Protocol as protocol
        from Log
        where (@LogId is null or LogId = @LogId) and
              (@LevelId is null or LevelId = @LevelId) and
              (@GroupId is null or LevelId in (select Gid from #GroupLevels)) and
              (@TimestampFrom is null or [timestamp] >= @TimestampFrom) and
              (@TimestampTo is null or [Timestamp] <= @TimestampTo) and
              (@ReceivedAtFrom is null or ReceivedAt >= @ReceivedAtFrom) and
              (@ReceivedAtTo is null or ReceivedAt <= @ReceivedAtTo) and
              (@Message = '' or contains([Message], @Message)) and
              (@CorrelationId = '' or CorrelationId = @CorrelationId) and
              (@Properties = '' or contains (PropertiesJson, @Properties)) and
              (@UserDefinition = '' or contains (UserDefinition, @UserDefinition)) and
              (@ClientIp = '' or ClientIp = @ClientIp) and
              (@ClientPort = '' or ClientPort = @ClientPort) and
              (@RequestPath = '' or RequestPath = @RequestPath) and
              (@Protocol = '' or Protocol = @Protocol) and
              (@SourceId is null or ClientIp + isnull(ClientPort, '') in (select address from @Sources)) and
              (
                  ufun_HasUserPermissionLevel(@Uid, LevelId) or
                  ufun_HasUserPermissionIpPort(@Uid, ClientIp, ClientPort) or
                  ufun_HasUserPermissionCorrelation(@Uid, CorrelationId) or
                  ufun_HasUserPermissionUserDefinition(@Uid, UserDefinition) or
                  ufun_HasUserPermissionRequestPath(@Uid, RequestPath)
                  )
        order by [Timestamp] desc
        offset @Off rows
        fetch next @PageSize rows only
        for json path, include_null_values, root('Logs');

        if object_id('tempdb..#GroupLevels') is not null     drop table #GroupLevels;
    end
end
go;

-- counts filtered result
create procedure usp_CountLogs (
    @Uid uniqueidentifier = null,
    @LogId bigint = null,
    @LevelId int = null,
    @GroupId int = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null,
    @Message nvarchar(max) = null,
    @CorrelationId nvarchar(100) = null,
    @Properties nvarchar(max) = null,
    @UserDefinition nvarchar(150) = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null,
    @RequestPath nvarchar(500) = null,
    @Protocol nvarchar(20) = null,
    @SourceId int = null
) as
begin
    set nocount on;

    set @Message = isnull(@Message, '');
    set @CorrelationId = isnull(@CorrelationId, '');
    set @Properties = isnull(@Properties, '');
    set @UserDefinition = isnull(@UserDefinition, '');
    set @ClientIp = isnull(@ClientIp, '');
    set @ClientPort = isnull(@ClientPort, '');
    set @RequestPath = isnull(@RequestPath, '');
    set @Protocol = isnull(@Protocol, '');

    declare @Sources table (address nvarchar(52))
    if @SourceId is not null
        insert into @Sources select isnull(ClientIp, '') + isnull(ClientPort, '')
        from Source
        where SourceId = @SourceId and
              ufun_HasUserPermissionIpPort (@Uid, ClientIp, ClientPort);

    select Count(*) as Cnt
    from Log as l
     join Level v on v.LevelId = l.LevelId
     join LevelGroup lg on v.LevelGroupId = lg.LevelGroupId
    where (@LogId is null or l.LogId = @LogId) and
        (@LevelId is null or l.LevelId = @LevelId) and
        (@GroupId is null or v.LevelGroupId = @GroupId) and
        (@TimestampFrom is null or l.[timestamp] >= @TimestampFrom) and
        (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
        (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
        (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
        (@Message = '' or contains(l.[Message], @Message)) and
        (@CorrelationId = '' or l.CorrelationId = @CorrelationId) and
        (@Properties = '' or contains (l.PropertiesJson, @Properties)) and
        (@UserDefinition = '' or contains (l.UserDefinition, @UserDefinition)) and
        (@ClientIp = '' or l.ClientIp = @ClientIp) and
        (@ClientPort = '' or l.ClientPort = @ClientPort) and
        (@RequestPath = '' or l.RequestPath = @RequestPath) and
        (@Protocol = '' or l.Protocol = @Protocol) and
        (@SourceId is null or l.ClientIp + isnull(l.ClientPort, '') in (select address from @Sources)) and
        (
            ufun_HasUserPermissionLevelGroup (@Uid, v.LevelGroupId) or
            ufun_HasUserPermissionLevel(@Uid, l.LevelId) or
            ufun_HasUserPermissionIpPort(@Uid, l.ClientIp, l.ClientPort) or
            ufun_HasUserPermissionCorrelation(@Uid, l.CorrelationId) or
            ufun_HasUserPermissionUserDefinition(@Uid, l.UserDefinition) or
            ufun_HasUserPermissionRequestPath(@Uid, l.RequestPath)
        )
    for json path, include_null_values, root('CountOfLogs');
end
go;

create procedure usp_ClearOldLogs (
    @Uid uniqueidentifier = null,
    @From datetime2(7) = null
) as
begin
    if ufun_IsAdmin(@Uid) = 0   throw 50000, 'Permission Denied', 1;
    if @From is null
        begin
            print '@From is empty...';
            return;
        end

    delete from Log where ReceivedAt < @From;
end
go;

-----------------------------------------------------------------------------------------

-- unknown logs
create procedure usp_GetUnknownLogs (
    @Uid uniqueidentifier = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select LogId as LogId,
           LevelId as level_id,
           [Timestamp] as timestamp,
           ReceivedAt as receivedAt,
           [Message] as message,
           CorrelationId as correlationId,
           PropertiesJson as propertiesAsJson,
           UserDefinition as userDefinition,
           ClientIp as clientIp,
           ClientPort as clientPort,
           RequestPath as requestPath,
           Protocol as protocol
    from Log
    where (
        LevelId is null
            or not exists (
            select 1
            from Source s
            where ClientIp = s.ClientIp and (ClientPort = s.ClientPort or (ClientPort is null and s.ClientPort is null)))
            ) and
        (@TimestampFrom is null or [Timestamp] >= @TimestampFrom) and
        (@TimestampTo is null or [Timestamp] <= @TimestampTo) and
        (@ReceivedAtFrom is null or ReceivedAt >= @ReceivedAtFrom) and
        (@ReceivedAtTo is null or ReceivedAt <= @ReceivedAtTo) and
        (
            ufun_HasUserPermissionLevel (@Uid, LevelId) or
            ufun_HasUserPermissionIpPort (@Uid, ClientIp, ClientPort) or
            ufun_HasUserPermissionUserDefinition (@Uid, UserDefinition) or
            ufun_HasUserPermissionRequestPath (@Uid, RequestPath) or
            ufun_HasUserPermissionCorrelation (@Uid, CorrelationId)
        )
    order by ReceivedAt, LogId
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('Logs');
end
go;

-- gets sequenced logs
create procedure usp_GetLogsForSequences (
    @Uid uniqueidentifier = null,
    @SeriCount int = null,
    @LevelId int = null,
    @GroupId int = null,
    @Message nvarchar(max) = null,
    @CorrelationId nvarchar(100) = null,
    @Property nvarchar(125) = null,
    @ForLevelId int = null,
    @ForGroupId int = null,
    @ForClientIp nvarchar(45) = null,
    @ForClientPort nvarchar(6) = null,
    @ForRequestPath nvarchar(500) = null,
    @ForProtocol nvarchar(20) = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null
) as
begin
    set nocount on;

    set @SeriCount = IIF(@SeriCount IS NULL, 2, IIF(@SeriCount > 2, @SeriCount, 2));
    set @Message = isnull(@Message, '');
    set @CorrelationId = isnull(@CorrelationId, '');
    set @Property = isnull(@Property, '');
    set @ForClientIp = isnull(@ForClientIp, '');
    set @ForClientPort = isnull(@ForClientPort, '');
    set @ForRequestPath = isnull(@ForRequestPath, '');
    set @ForProtocol = isnull(@ForProtocol, '');

    ;with c1 as (
        select l.LogId as LogId,
               l.LevelId as level_id,
               l.[Timestamp] as timestamp,
               l.ReceivedAt as receivedAt,
               l.[Message] as message,
               l.CorrelationId as correlationId,
               l.PropertiesJson as propertiesAsJson,
               lg.LevelGroupId as group_id,
               row_number() over (order by l.LogId) rn
        from Log as l
                 left join Level lv on l.LevelId = lv.LevelId
                 left join LevelGroup lg on lv.LevelGroupId = lg.LevelGroupId
        where (@ForLevelId is null or l.LevelId = @ForLevelId) and
            (@ForGroupId is null or  lv.LevelGroupId = @ForGroupId) and
            (@ForClientIp = '' or l.ClientIp = @ForClientIp) and
            (@ForClientPort = '' or l.ClientPort = @ForClientPort) and
            (@ForRequestPath = '' or l.RequestPath = @ForRequestPath) and
            (@ForProtocol = '' or l.Protocol = @ForProtocol) and
            (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
            (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
            (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
            (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
            (
                ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
                ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
                )
    ), c2 as (
        select cc.level_id,
               cc.group_id,
               cc.receivedAt,
               cc.timestamp,
               cc.rn - row_number() over (order by cc.LogId) as fin_rn
        from c1 cc
        where (@LevelId is null or cc.level_id = @LevelId) and
               (@GroupId is null or cc.group_id = @GroupId) and
               (@Message = '' or contains (cc.message, @Message)) and
               (@CorrelationId = '' or cc.correlationId = @CorrelationId) and
               (@Property = '' or contains (cc.propertiesAsJson, @Property))
    ), c3 as (
        select fin_rn,
               group_id,
               level_id,
               Count(*) as count_of_logs,
               Min(receivedAt) as first_received,
               Min([timestamp]) as first_time,
               Max(receivedAt) as last_received,
               Max([timestamp]) as last_time
        from c2
        group by fin_rn, group_id, level_id
        having Count(*) >= @SeriCount
    )
    select group_id,
           level_id,
           count_of_logs,
           first_received,
           first_time,
           last_received,
           last_time
    from c3
    for json path, include_null_values, root('Logs');

end
go;

-- Title of log
create function ufun_GetTitle (
    @Level nvarchar(50) = null,
    @Message nvarchar(max) = null
) returns nvarchar(max)
as
begin
    return IIF(@Level is not null or @Message is not null,
               isnull(left(@Message, 16) + '...', '') + ' (' + isnull(@Level, '') + ')',
               null )
end
go;

-- gets alternatives and traces of each log
create procedure usp_AlternativeLogs (
    @Uid uniqueidentifier = null,
    @LevelId int = null,
    @GroupId int = null,
    @Message nvarchar(max) = null,
    @CorrelationId nvarchar(100) = null,
    @Property nvarchar(150) = null,
    @UserDefinition nvarchar(150) = null,
    @ClientIp nvarchar(45) = null,
    @ClientPort nvarchar(6) = null,
    @RequestPath nvarchar(500) = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null
) as
begin
    set nocount on;

    set @Message = isnull(@Message, '');
    set @CorrelationId = isnull(@CorrelationId, '');
    set @Property = isnull(@Property, '');
    set @UserDefinition = isnull(@UserDefinition, '');
    set @ClientIp = isnull(@ClientIp, '');
    set @ClientPort = isnull(@ClientPort, '');
    set @RequestPath = isnull(@RequestPath, '');

    ;with c1 as (
        select l.LogId as LogId,
               l.Message + ' (' + isnull(lv.Name, '-') + '(' + isnull(lg.Name, '-') + '))'  as Inf,
               ufun_GetTitle(
                       lag(lv.Name) over ( order by l.[Timestamp], l.LogId),
                       lag(l.Message) over ( order by l.[Timestamp], l.LogId)
               ) as LagTitle1,
               ufun_GetTitle(
                       lag(lv.Name, 2) over ( order by l.[Timestamp], l.LogId),
                       lag(l.Message, 2) over ( order by l.[Timestamp], l.LogId)
               ) as LagTitle2,
               lag(l.LogId) over ( order by l.[Timestamp], l.LogId) as LagId1,
               lag(l.LogId, 2) over ( order by l.[Timestamp], l.LogId) as LagId2,
               ufun_GetTitle(
                       lead(lv.Name) over ( order by l.[Timestamp], l.LogId),
                       lead(l.Message) over ( order by l.[Timestamp], l.LogId)
               ) as Follows,
               lead(l.LogId) over ( order by l.[Timestamp], l.LogId) as LeadId
        from Log as l
                 left join Level lv on l.LevelId = lv.LevelId
                 left join LevelGroup lg on lv.LevelGroupId = lg.LevelGroupId
        where (@LevelId is null or @LevelId = l.LevelId) and
            (@GroupId is null or @GroupId = lv.LevelGroupId) and
            (@Message is null or contains (l.Message, @Message)) and
            (@CorrelationId is null or l.CorrelationId = @CorrelationId) and
            (@Property is null or contains (l.PropertiesJson, @Property)) and
            (@UserDefinition is null or contains (l.UserDefinition, @UserDefinition)) and
            (@ClientIp is null or l.ClientIp = @ClientIp) and
            (@ClientPort is null or l.ClientPort = @ClientPort) and
            (@RequestPath is null or contains (l.RequestPath, @RequestPath)) and
            (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
            (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
            (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
            (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
            (
                ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
                ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
                )
    )
    select l.LogId as id,
           tr.Inf as LogDetailes,
           l.Timestamp as [timestamp],
           l.ReceivedAt as receivedAt,
           l.CorrelationId as correlationId,
           l.PropertiesJson as properties,
           l.UserDefinition as userDefinition,
           l.ClientIp as ip,
           l.ClientPort as port,
           l.RequestPath as requestPath,
           Concat(isnull(tr.LagTitle2, ''), ' -->', isnull(tr.LagTitle1, ''), ' -->') as trace,
           Concat('--> ', isnull(tr.Follows, '')) as following,
           tr.LagId1 as lagId1,
           tr.LagId2 as lagId2,
           tr.LeadId as leadId,
           Count(*) over ( partition by tr.LagTitle1, tr.Inf ) as countOfDuplicates,
           Count(*) over ( partition by tr.LagTitle1, tr.Inf order by l.[Timestamp] ) as runningCountOfDuplicates,
           First_Value(l.Timestamp) over ( partition by tr.LagTitle1, tr.Inf
                                           rows between unbounded preceding and unbounded following )  as firstTimeHappen,
           Last_Value(l.Timestamp) over ( partition by tr.LagTitle1, tr.Inf
                                          rows between unbounded preceding and unbounded following )  as LastTimeHappen,
           First_Value(l.LogId) over ( partition by tr.LagTitle1, tr.Inf
                                       rows between unbounded preceding and unbounded following )  as firstLogId,
           Last_Value(l.LogId) over ( partition by tr.LagTitle1, tr.Inf
                                      rows between unbounded preceding and unbounded following )  as LastLogId,
           Count(*) over ( partition by tr.Follows, tr.Inf ) > 1 as isPartOfCluster
    from c1 tr
    join Log l on tr.LogId = l.LogId
    order by l.Timestamp, l.LogId
    for json path, include_null_values, root('Logs');

end
go;

-- creates pivot data and counts logs
create procedure usp_CreatePivot (
    @Uid uniqueidentifier = null,
    @Per datetime2 = null,
    @Unit nvarchar(10) = null,
    @Which nvarchar(16) = null,
    @Values nvarchar(max) = null
) as
begin
    set nocount on;

    if @Unit not in ('Hour', 'Day', 'Week', 'Month', 'Year', 'All')
          throw 50000, 'Invalid value for @Unit', 1;
    if @Which not in ('GroupId', 'LevelId', 'SourceId', 'Message', 'CorrelationId', 'ClientIp', 'RequestPath')
          throw 50000, 'Invalid value for @Which', 1;
    if (@Per is null and @Unit <> 'All') or @Values is null
          throw 50000, 'All arguments are required', 1;

    declare @Vals table (i nvarchar(max));
    insert into @Vals
    select value from string_split(@Values, ',');

    create table #Datas (LogId int, [Count] int, Alias nvarchar(255)) with (memory_optimized = on);

    insert into #Datas
    select LogId as LogId,
       case when @Unit = 'All' then datepart(year, l.[Timestamp])
            when @Unit = 'Year' then datepart(month, l.[Timestamp])
            when @Unit = 'Month' then day(try_cast(l.[Timestamp] as date))
            when @Unit = 'Week' then datepart(weekday , l.[Timestamp])
            when @Unit = 'Day' then datepart(hour, l.[Timestamp])
            when @Unit = 'Hour' then datepart(minute, l.[Timestamp])
            else -1
            end  as [Count],
        case when @Which = 'GroupId' then lg.Name
            when @Which = 'LevelId' then isnull(lv.Name + ':' + lg.Name, 'Unknown')
            when @Which = 'SourceId' then s.Name
            when @Which = 'Message' then left(l.Message, 250) + '...'
            when @Which = 'CorrelationId' then isnull(l.CorrelationId, 'Unknown')
            when @Which = 'ClientIp' then isnull(l.ClientIp, 'Unknown')
            when @Which = 'RequestPath' then isnull(l.RequestPath, 'Unknown')
            else 'Unselected'
            end  as Alias
    from Log l
    left join Level lv on l.LevelId = lv.LevelId
    left join LevelGroup lg on lv.LevelGroupId = lg.LevelGroupId
    left join Source s on l.ClientIp = s.ClientIp and (l.ClientPort = s.ClientPort or (l.ClientPort is null and s.ClientPort is null))
    where (@Unit not in ('Hour', 'Day', 'Week', 'Month', 'Year') or datepart(year, l.[Timestamp]) = datepart(year, @Per)) and
        (@Unit not in ('Hour', 'Day', 'Week', 'Month') or datepart(month, l.[Timestamp]) = datepart(month, @Per)) and
        (@Unit not in ('Hour', 'Day', 'Week') or datepart(week, l.[Timestamp]) = datepart(week, @Per)) and
        (@Unit not in ('Hour', 'Day') or datepart(day, l.[Timestamp]) = datepart(day, @Per)) and
        (@Unit <> 'Hour' or datepart(hour, l.[Timestamp]) = datepart(hour, @Per)) and
        (@Which <> 'GroupId' or lv.LevelGroupId in (select distinct try_cast(i as int) from @Vals except select null)) and
        (@Which <> 'LevelId' or l.LevelId in (select distinct try_cast(i as int) from @Vals except select null)) and
        (@Which <> 'SourceId' or s.SourceId in (select distinct try_cast(i as int) from @Vals except select null)) and
        (@Which <> 'Message' or l.Message in (select distinct i from @Vals except select null)) and
        (@Which <> 'CorrelationId' or l.CorrelationId in (select distinct i from @Vals except select null)) and
        (@Which <> 'ClientIp' or l.ClientIp in (select distinct i from @Vals except select null)) and
        (@Which <> 'RequestPath' or l.RequestPath in (select distinct i from @Vals except select null)) and
        (
            ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
            ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
            ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
            ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
            ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
            ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
        );

    if @Unit = 'All'
    begin
        declare @Cols nvarchar(max) = (select String_Agg('[' + Cast(Year([Timestamp]) as nvarchar(4)) + ']', ',') from Log);
        declare @Q nvarchar(max) =
        'select Alias, ' + @Cols + '
        from #Datas
                 pivot (
                 count(LogId) for [Count] in (' + @Cols + ')
                 ) as pivot_data
        order by Alias
        for json path, include_null_values, root(''Pivot'');';
        exec sp_executesql @Q;
    end

    if @Unit = 'Year'
    begin
        select Alias, [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12]
        from #Datas
                 pivot (
                 count(LogId) for [Count] in ([1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12])
                 ) as pivot_data
        order by Alias
        for json path, include_null_values, root('Pivot');
    end

    if @Unit = 'Month'
    begin
        select Alias, [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15], [16], [17], [18], [19], [20], [21], [22], [23], [24], [25], [26], [27], [28], [29], [30], [31]
        from #Datas
                 pivot (
                 count(LogId) for [Count] in ([1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15], [16], [17], [18], [19], [20], [21], [22], [23], [24], [25], [26], [27], [28], [29], [30], [31])
                 ) as pivot_data
        order by Alias
        for json path, include_null_values, root('Pivot');
    end

    if @Unit = 'Week'
    begin
        select Alias, [1], [2], [3], [4], [5], [6], [7]
        from #Datas
                 pivot (
                 count(LogId) for [Count] in ([1], [2], [3], [4], [5], [6], [7])
                 ) as pivot_data
        order by Alias
        for json path, include_null_values, root('Pivot');
    end

    if @Unit = 'Day'
    begin
        select Alias, [0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15], [16], [17], [18], [19], [20], [21], [22], [23]
        from #Datas
                 pivot (
                 count(LogId) for [Count] in ([0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15], [16], [17], [18], [19], [20], [21], [22], [23])
                 ) as pivot_data
        order by Alias
        for json path, include_null_values, root('Pivot');
    end

    if @Unit = 'Hour'
    begin
        select Alias, [0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15], [16], [17], [18], [19], [20], [21], [22], [23], [24], [25], [26], [27], [28], [29], [30], [31], [32], [33], [34], [35], [36], [37], [38], [39], [40], [41], [42], [43], [44], [45], [46], [47], [48], [49], [50], [51], [52], [53], [54], [55], [56], [57], [58], [59]
        from #Datas
                 pivot (
                 count(LogId) for [Count] in ([0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15], [16], [17], [18], [19], [20], [21], [22], [23], [24], [25], [26], [27], [28], [29], [30], [31], [32], [33], [34], [35], [36], [37], [38], [39], [40], [41], [42], [43], [44], [45], [46], [47], [48], [49], [50], [51], [52], [53], [54], [55], [56], [57], [58], [59])
                 ) as pivot_data
        order by Alias
        for json path, include_null_values, root('Pivot');
    end

    if object_id('tempdb..#Datas') is not null     drop table #Datas;
end
go;

-- ranking bases of counting the logs
create procedure usp_RankLogs (
    @Uid uniqueidentifier = null,
    @Groups bit = null,
    @Levels bit = null,
    @Sources bit = null,
    @Messages bit = null,
    @CorrelationIds bit = null,
    @ClientIps bit = null,
    @RequestPaths bit = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    if @Groups = 0 and @Levels = 0 and @Sources = 0 and @Messages = 0 and @CorrelationIds = 0 and @ClientIps = 0 and @RequestPaths = 0
    begin
        print 'You should choose one or more operation...';
        return;
    end

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    if @Groups = 1
    begin
        ;with c1 as (
            select lg.LevelGroupId as levelGroupId,
                   lg.Name as name,
                   Count(*) as [count]
            from Log as l
            join Level lv on l.LevelId = lv.LevelId
            join LevelGroup lg on lv.LevelGroupId = lg.LevelGroupId
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
                    ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
                )
            group by lg.LevelGroupId, lg.Name
        )
        select levelGroupId,
               name,
               [count],
               dense_rank() over ( order by [count] desc ) as [rank]
        from c1
        order by [count] desc
        offset @Off rows
        fetch next @PageSize rows only
        for json path, include_null_values, root('Logs');
    end

    if @Levels = 1
    begin
        ;with c1 as (
            select lv.LevelId as levelId,
                   lv.Name as name,
                   Count(*) as [count]
            from Log as l
            join Level lv on l.LevelId = lv.LevelId
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
                    ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
                )
            group by lv.LevelId, lv.Name
        )
         select levelId,
                name,
                [count],
                dense_rank() over ( order by [count] desc ) as [rank]
         from c1
         order by [count] desc
         offset @Off rows
         fetch next @PageSize rows only
         for json path, include_null_values, root('Logs');
    end

    if @Sources = 1
    begin
        ;with c1 as (
            select s.SourceId as SourceId,
                   s.Name as name,
                   Count(*) as [count]
            from Log as l
            join Source s on l.ClientIp = s.ClientIp and (l.ClientPort = s.ClientPort or (l.ClientPort is null and s.ClientPort is null))
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by s.SourceId, s.Name
        )
         select SourceId,
                name,
                [count],
                dense_rank() over ( order by [count] desc ) as [rank]
         from c1
         order by [count] desc
         offset @Off rows
         fetch next @PageSize rows only
         for json path, include_null_values, root('Logs');
    end

    if @Messages = 1
    begin
        ;with c1 as (
            select l.LevelId as levelId,
                   Left(l.Message, 175) as message,
                   Count(*) as [count]
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.Message, l.LevelId
        )
         select levelId,
                message,
                [count],
                dense_rank() over ( order by [count] desc ) as [rank]
         from c1
         order by [count] desc
         offset @Off rows
         fetch next @PageSize rows only
         for json path, include_null_values, root('Logs');
    end

    if @CorrelationIds = 1
    begin
        ;with c1 as (
            select l.LevelId as levelId,
                   l.CorrelationId as correationId,
                   Count(*) as [count]
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.CorrelationId, l.LevelId
        )
         select levelId,
                correationId,
                [count],
                dense_rank() over ( order by [count] desc ) as [rank]
         from c1
         order by [count] desc
         offset @Off rows
         fetch next @PageSize rows only
         for json path, include_null_values, root('Logs');
    end

    if @ClientIps = 1
    begin
        ;with c1 as (
            select l.LevelId as levelId,
                   l.ClientIp as clientIp,
                   Count(*) as [count]
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.ClientIp, l.LevelId
        )
         select levelId,
                clientIp,
                [count],
                dense_rank() over ( order by [count] desc ) as [rank]
         from c1
         order by [count] desc
         offset @Off rows
         fetch next @PageSize rows only
         for json path, include_null_values, root('Logs');
    end

    if @RequestPaths = 1
    begin
        ;with c1 as (
            select l.LevelId as levelId,
                   l.RequestPath as requestPath,
                   Count(*) as [count]
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.RequestPath, l.LevelId
        )
         select levelId,
                requestPath,
                [count],
                dense_rank() over ( order by [count] desc ) as [rank]
         from c1
         order by [count] desc
         offset @Off rows
         fetch next @PageSize rows only
         for json path, include_null_values, root('Logs');
    end
end
go;

-- gets delayed logs
create procedure usp_GetDelayedLogs (
    @Uid uniqueidentifier = null,
    @DelaysInMilliseconds int = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null,
    @Page int = null,
    @PageSize int = null
) as
begin
    set nocount on;

    if @Page is null    set @Page = 1;
    if @PageSize is null    set @PageSize = 2500;
    declare @Off int = (@Page - 1) * @PageSize;

    select l.LogId as logId,
           lv.Name as levelName,
           lg.Name as groupName,
           l.Message as message,
           l.[Timestamp] as [timestamp],
           l.ReceivedAt as recivedAt,
           datediff(millisecond , l.[Timestamp], l.ReceivedAt) >= @DelaysInMilliseconds as timeDifferenceInMilliseconds,
           l.ClientIp as clientIp,
           l.ClientPort as clientPort,
           l.CorrelationId as CorrelationId,
           l.UserDefinition as userDefinition,
           l.PropertiesJson as properties,
           l.Protocol as protocol,
           l.RequestPath as requestPath
    from Log as l
    left join Level as lv on l.LevelId = lv.LevelId
    left join LevelGroup as lg on lv.LevelGroupId = lg.LevelGroupId
    where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
        (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
        (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
        (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
        datediff(millisecond , l.[Timestamp], l.ReceivedAt) >= @DelaysInMilliseconds and
        (
            ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
            ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
            ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
            ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
            ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
            ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
        )
    order by l.ReceivedAt desc, l.LogId
    offset @Off rows
    fetch next @PageSize rows only
    for json path, include_null_values, root('Logs');
end
go;

-- gets things those got less log
create procedure usp_GetThingsWithLessLog (
    @Uid uniqueidentifier = null,
    @Groups bit = null,
    @Levels bit = null,
    @Sources bit = null,
    @Messages bit = null,
    @CorrelationIds bit = null,
    @ClientIps bit = null,
    @RequestPaths bit = null,
    @MinCount int = null,
    @TimestampFrom datetime2(7) = null,
    @TimestampTo datetime2(7) = null,
    @ReceivedAtFrom datetime2 = null,
    @ReceivedAtTo datetime2 = null
) as
begin
    set nocount on;

    if @Groups = 0 and @Levels = 0 and @Sources = 0 and @Messages = 0 and @CorrelationIds = 0 and @ClientIps = 0 and @RequestPaths = 0
        begin
            print 'You should choose one or more operation...';
            return;
        end

    set @MinCount = isnull(@MinCount, 0)

    if @Groups = 1
        begin
            select lg.LevelGroupId as levelGroupId,
                   lg.Name as name,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
                     join Level lv on l.LevelId = lv.LevelId
                     join LevelGroup lg on lv.LevelGroupId = lg.LevelGroupId
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
                    ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
                )
            group by lg.LevelGroupId, lg.Name
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end

    if @Levels = 1
        begin
            select lv.LevelId as levelId,
                   lv.Name as name,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
                     join Level lv on l.LevelId = lv.LevelId
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId) or
                    ufun_HasUserPermissionLevelGroup (@Uid, lv.LevelGroupId)
                )
            group by lv.LevelId, lv.Name
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end

    if @Sources = 1
        begin
            select s.SourceId as SourceId,
                   s.Name as name,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
                     join Source s on l.ClientIp = s.ClientIp and (l.ClientPort = s.ClientPort or (l.ClientPort is null and s.ClientPort is null))
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by s.SourceId, s.Name
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end

    if @Messages = 1
        begin
            select l.LevelId as levelId,
                   Left(l.Message, 175) as message,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.Message, l.LevelId
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end

    if @CorrelationIds = 1
        begin
            select l.LevelId as levelId,
                   l.CorrelationId as correationId,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.CorrelationId, l.LevelId
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end

    if @ClientIps = 1
        begin
            select l.LevelId as levelId,
                   l.ClientIp as clientIp,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.ClientIp, l.LevelId
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end

    if @RequestPaths = 1
        begin
            select l.LevelId as levelId,
                   l.RequestPath as requestPath,
                   Count(*) as [count],
                   Max(l.ReceivedAt) as lastTimeReceved
            from Log as l
            where (@TimestampFrom is null or l.[Timestamp] >= @TimestampFrom) and
                (@TimestampTo is null or l.[Timestamp] <= @TimestampTo) and
                (@ReceivedAtFrom is null or l.ReceivedAt >= @ReceivedAtFrom) and
                (@ReceivedAtTo is null or l.ReceivedAt <= @ReceivedAtTo) and
                (
                    ufun_HasUserPermissionLevel (@Uid, l.LevelId) or
                    ufun_HasUserPermissionIpPort (@Uid, l.ClientIp, l.ClientPort) or
                    ufun_HasUserPermissionUserDefinition (@Uid, l.UserDefinition) or
                    ufun_HasUserPermissionRequestPath (@Uid, l.RequestPath) or
                    ufun_HasUserPermissionCorrelation (@Uid, l.CorrelationId)
                )
            group by l.RequestPath, l.LevelId
            having Count(*) <= @MinCount
            for json path, include_null_values, root('Results');
        end
end
go;

-----------------------------------------------------------------------------------------

print('Database was initialized successfully! ');