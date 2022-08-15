SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[DeletePath]
@GroupGUID VARCHAR(36),
@CheckGUID VARCHAR(36),
@PathGUID VARCHAR(36)
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
        SET @Message = 'check does not exist for GUID: ' + @CheckGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @PathID INT
    SELECT @PathID = ID FROM [authz].[PATHS] WHERE CheckID = @CheckID AND GUID = @PathGUID
    IF @PathID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'path does not exist for GUID: ' + @PathGUID;
        THROW @ReturnCode, @Message, 1;
    END

		DELETE FROM [authz].[PATHS] WHERE ID = @PathID

    SELECT 'path deleted for GUID ' + @PathGUID

    END TRY
  
    BEGIN CATCH
        IF ERROR_NUMBER() > 50000
        BEGIN
            THROW;
        END
        DECLARE @ErrorMessage VARCHAR(400)
        SELECT @ErrorMessage = 'Delete path failed for GUID ' + @PathGUID + ': ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
