ALTER PROCEDURE [authz].[UpdateHost]
    @SessionGUID VARCHAR(36),
    @GroupGUID VARCHAR(36),
    @HostGUID VARCHAR(36),
    @Hostname VARCHAR(256)
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
        SET @Message = 'host group does not exist for: ' + @GroupGUID;
        THROW @ReturnCode, @Message, 1;
    END
    
    DECLARE @HostID INT
    SELECT @HostID = ID
    FROM [authz].[HOSTS]
    WHERE GroupID = @GroupID AND GUID = @HostGUID
    IF @HostID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'host does not exist for group ' + @GroupGUID + ' for host ' + @HostGUID;
        THROW @ReturnCode, @Message, 1;
    END

  	UPDATE [authz].[HOSTS]
	  	SET [Hostname] = @Hostname, [UpdateUser] =	@SessionGUID
	  WHERE ID = @HostID

		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [h].[GUID] AS "guid",
        [h].[Hostname] AS "hostname",
        FORMAT([h].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
        [h].CreateUser AS "createUser",
        FORMAT([h].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
        [h].UpdateUser AS "updateUser"
    FROM [authz].HOSTS [h]
    WHERE [h].ID = @HostID
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
