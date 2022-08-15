SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[GetChecks]
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
      (SELECT [ch].GUID AS "guid", 
              [ch].Name AS "name",
              [ch].Description AS "description",
              [ch].Version AS "version",
              [ch].Base AS "base",
              FORMAT([ch].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [ch].CreateUser AS "createUser",
              FORMAT([ch].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [ch].UpdateUser AS "updateUser"
       FROM [authz].CHECKS [ch]
       WHERE GroupID = @GroupID
       FOR JSON PATH, INCLUDE_NULL_VALUES)
       
    SELECT ISNULL(@json, '[]')
    
    END TRY
  
    BEGIN CATCH
        IF ERROR_NUMBER() > 50000
        BEGIN
            THROW;
        END
        DECLARE @ErrorMessage VARCHAR(400)
        SELECT @ErrorMessage = 'get host checks failed: ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH

END
GO
