ALTER PROCEDURE [authz].[DeleteHost]
    @GroupGUID VARCHAR(36),
    @HostGUID VARCHAR(256)
WITH
    EXEC AS CALLER
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
    
    DECLARE @HostID INT
    SELECT @HostID = ID
    FROM [authz].[HOSTS]
    WHERE GroupID = @GroupID AND GUID = @HostGUID
    IF @HostID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host does not exist in group ' + @GroupGUID + ' with GUID: ' + @HostID;
        THROW @ReturnCode, @Message, 1;
    END

		DELETE FROM [authz].[HOSTS]
		WHERE GroupID = @GroupID AND ID = @HostID

    SELECT 'deleted host ' + @HostGUID + ' in group ' + @GroupGUID

    END TRY
  
    BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
        THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'delete host failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
    END CATCH
END
