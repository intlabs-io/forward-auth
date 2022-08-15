SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[UpdatePath]
@SessionGUID VARCHAR(36),
@GroupGUID VARCHAR(36),
@CheckGUID VARCHAR(36),
@PathGUID VARCHAR(36),
@Path VARCHAR(1024),
@Rules NVARCHAR(max)
WITH EXEC AS CALLER
AS
BEGIN
    DECLARE @BaseCode INT = 50000
    DECLARE @ReturnCode INT
    DECLARE @Message VARCHAR(200)

    BEGIN TRY
    
    DECLARE @GroupID INT
    SELECT @GroupID = ID FROM [authz].[HOST_GROUPS] WHERE GUID = @GroupGUID
    IF @GroupID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host group does not exist for GUID ' + @GroupGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @CheckID INT
    SELECT @CheckID = ID FROM [authz].[CHECKS] WHERE GroupID = @GroupID AND GUID = @CheckGUID
    IF @CheckID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host check does not exist for group ' + @GroupGUID + ' with ' + @CheckGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @PathID INT
    SELECT @PathID = ID FROM [authz].[PATHS] WHERE CheckID = @CheckID AND GUID = @PathGUID
    IF @PathID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'path does not exist for pathGUID: ' + @PathGUID;
        THROW @ReturnCode, @Message, 1;
    END

  	UPDATE [authz].[PATHS] SET [Path] = @Path, [Rules] = @Rules, [UpdateUser] =	@SessionGUID 
  	WHERE ID = @PathID

		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [p].[GUID] AS "guid", 
              [p].[Path] AS "path",
              JSON_QUERY([p].[Rules]) AS "rules",
              FORMAT([p].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [p].CreateUser AS "createUser",
              FORMAT([p].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [p].UpdateUser AS "updateUser"
       FROM [authz].PATHS [p]
       WHERE [p].ID = @PathID
       FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
       
    SELECT @json

    END TRY
  
    BEGIN CATCH
        IF ERROR_NUMBER() > 50000
        BEGIN
            THROW;
        END
        DECLARE @ErrorMessage VARCHAR(400)
        SELECT @ErrorMessage = 'update path failed: ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
