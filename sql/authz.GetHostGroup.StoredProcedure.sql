SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[GetHostGroup]
@GroupGUID VARCHAR(36)
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
        SET @Message = 'host group does not exist for GUID: ' + @GroupGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [hg].GUID AS "guid", 
              [hg].Name AS "name",
              [hg].[Default] AS "default",
              [hg].Description AS "description",
              JSON_QUERY([authz].HostsJSON([hg].ID)) AS "hosts",
              JSON_QUERY([authz].ChecksJSON([hg].ID)) AS "checks",
              FORMAT([hg].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [hg].CreateUser AS "createUser",
              FORMAT([hg].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [hg].UpdateUser AS "updateUser"
       FROM [authz].HOST_GROUPS [hg]
       WHERE [hg].ID = @GroupID
       FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
       
    SELECT @json

    END TRY
  
    BEGIN CATCH
        IF ERROR_NUMBER() > 50000
        BEGIN
            THROW;
        END
        DECLARE @ErrorMessage VARCHAR(400)
        SELECT @ErrorMessage = 'get host group failed for GUID ' + @GroupGUID + ': ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
