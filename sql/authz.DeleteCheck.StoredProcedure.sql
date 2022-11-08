SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[DeleteCheck]
@GroupGUID VARCHAR(36),
@CheckGUID VARCHAR(36)
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

    BEGIN TRANSACTION
    
      DELETE FROM [authz].[PATHS] WHERE CheckID = @CheckID 
	  	DELETE FROM [authz].[CHECKS] WHERE ID = @CheckID
    
    COMMIT TRANSACTION
    
    SELECT 'deleted check with GUID ' + @CheckGUID

    END TRY
  
    BEGIN CATCH
       IF @@TRANCOUNT > 0
       BEGIN
         ROLLBACK TRANSACTION
       END
       IF ERROR_NUMBER() > 50000
       BEGIN
           THROW;
       END
       DECLARE @ErrorMessage VARCHAR(400)
       SELECT @ErrorMessage = 'Delete check failed for GUID ' + @CheckGUID + ': ' + ERROR_MESSAGE();
       THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO