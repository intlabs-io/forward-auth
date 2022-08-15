SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[GetCheck]
@GroupGUID VARCHAR(36),
@CheckGUID VARCHAR(36)
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
    
    DECLARE @CheckID INT
    SELECT @CheckID = ID FROM [authz].[CHECKS] WHERE GroupID = @GroupID AND GUID = @CheckGUID
    IF @CheckID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host check does not exist for GUID: ' + @CheckGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [ch].GUID AS "guid", 
              [ch].Name AS "name",
              [ch].[Description] AS "description",
              [ch].[Version] AS "version",
              [ch].[Base] AS "base",
              FORMAT([ch].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [ch].CreateUser AS "createUser",
              FORMAT([ch].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [ch].UpdateUser AS "updateUser"
       FROM [authz].CHECKS [ch]
       WHERE [ch].ID = @CheckID
       FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
       
    SELECT @json
    
    END TRY
  
    BEGIN CATCH
        IF ERROR_NUMBER() > 50000
        BEGIN
            THROW;
        END
        DECLARE @ErrorMessage VARCHAR(400)
        SELECT @ErrorMessage = 'get check failed for GUID ' + @CheckGUID + ': ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
