ALTER PROCEDURE [authz].[GetPath]
    @GroupGUID VARCHAR(36),
    @CheckGUID VARCHAR(36),
    @PathGUID VARCHAR(36)
AS 
BEGIN

    DECLARE @BaseCode INT = 50000
    DECLARE @ReturnCode INT
    DECLARE @Message VARCHAR(200)

    BEGIN TRY
    
    DECLARE @GroupID INT
    SELECT @GroupID = ID
    FROM [authz].[HOST_GROUPS]
    WHERE GUID = @GroupGUID
    IF @GroupID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host group does not exist for GUID: ' + @GroupGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @CheckID INT
    SELECT @CheckID = ID
    FROM [authz].[CHECKS]
    WHERE GroupID = @GroupID AND GUID = @CheckGUID
    IF @CheckID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host check does not exist for GUID: ' + @CheckGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @PathID INT
    SELECT @PathID = ID
    FROM [authz].[PATHS]
    WHERE GUID = @PathGUID
    IF @PathID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'path does not exist for GUID: ' + @PathGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [p].GUID AS "guid",
        [p].Path AS "path",
        [p].[Rules] AS "rules",
        FORMAT([p].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
        [p].CreateUser AS "createUser",
        FORMAT([p].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
        [p].UpdateUser AS "updateUser"
    FROM [authz].PATHS [p]
    WHERE [p].ID = @PathID
    FOR JSON PATH, INCLUDE_NULL_VALUES)
       
    SELECT @json
    
    END TRY
  
    BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
        THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'get path failed for GUID ' + @PathGUID + ': ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
    END CATCH
END