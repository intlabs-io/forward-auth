ALTER PROCEDURE [authz].[CreateHost]
    @SessionGUID VARCHAR(36),
    @GroupGUID VARCHAR(36),
    @Hostname VARCHAR(256),
    @GUID VARCHAR(36) OUTPUT
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

		INSERT INTO [authz].[HOSTS]
        (
        [GUID],
        [GroupID],
        [Hostname],
        [CreateUser],
        [UpdateUser])
    VALUES
        (
            newid(),
            @GroupID,
            @Hostname,
            @SessionGUID,
            @SessionGUID);

		DECLARE @ID INT
		SELECT @ID = SCOPE_IDENTITY()
		
		SELECT @GUID = GUID
    FROM [authz].[HOSTS]
    WHERE ID = @ID
		
		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [h].GUID AS "guid",
        [h].Hostname AS "name",
        FORMAT([h].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
        [h].CreateUser AS "createUser",
        FORMAT([h].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
        [h].UpdateUser AS "updateUser"
    FROM [authz].HOSTS [h]
    WHERE [h].ID = @ID
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
       
    SELECT @json

    END TRY
  
    BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
        THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'Create host failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
    END CATCH
END
