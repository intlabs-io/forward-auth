ALTER PROCEDURE [authz].[CreatePath]
    @SessionGUID VARCHAR(36),
    @CheckGUID VARCHAR(36),
    @Path VARCHAR(1024),
    @Rules NVARCHAR(max),
    @GUID VARCHAR(36) OUTPUT
WITH
    EXEC AS CALLER
AS
BEGIN
    DECLARE @BaseCode INT = 50000
    DECLARE @ReturnCode INT
    DECLARE @Message VARCHAR(200)

    BEGIN TRY
    
    DECLARE @CheckID INT
    SELECT @CheckID = ID
    FROM [authz].[CHECKS]
    WHERE GUID = @CheckGUID
    IF @CheckID IS NULL
    BEGIN
        SET @ReturnCode = @BaseCode + 404;
        SET @Message = 'check does not exist for GUID: ' + @CheckGUID;
        THROW @ReturnCode, @Message, 1;
    END


  		INSERT INTO [authz].[PATHS]
        (
        [GUID],
        [CheckID],
        [Path],
        [Rules],
        [CreateUser],
        [UpdateUser])
    VALUES
        (
            newid(),
            @CheckID,
            @Path,
            @Rules,
            @SessionGUID,
            @SessionGUID);

		DECLARE @ID INT
		SELECT @ID = SCOPE_IDENTITY()
		
		SELECT @GUID = GUID
    FROM [authz].[PATHS]
    WHERE ID = @ID
		
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
    WHERE [p].ID = @ID
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
       
    SELECT @json

    END TRY
  
    BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
        THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'Create path failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
    END CATCH
END
