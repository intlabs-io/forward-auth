SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[UpdateCheck]
@SessionGUID VARCHAR(36),
@GroupGUID VARCHAR(36),
@CheckGUID VARCHAR(36),
@Name VARCHAR(32),
@Description VARCHAR(256),
@Version INT,
@Base VARCHAR(128)
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
        SET @Message = 'host group does not exist for GUID: ' + @GroupGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @CheckID INT
    SELECT @CheckID = ID FROM [authz].[CHECKS] WHERE GroupID = @GroupID AND GUID = @CheckGUID
    IF @CheckID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'check does not exist for checkGUID: ' + @CheckGUID;
        THROW @ReturnCode, @Message, 1;
    END

  	UPDATE [authz].[CHECKS]	SET [NAME] = @Name, [Description] = @Description, [Version] = @Version, [Base] = @Base, [UpdateUser]=	@SessionGUID
	  WHERE ID = @CheckID

		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [ch].[GUID] AS "guid", 
              [ch].[Name] AS "name",
              [ch].Description AS "description",
              [ch].Version AS "version",
              [ch].Base AS "base",
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
        SELECT @ErrorMessage = 'update path failed: ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
