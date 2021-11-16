ALTER PROCEDURE [authz].[CreateHostGroup]
    @SessionGUID VARCHAR(36),
    @Name VARCHAR(32),
    @Description VARCHAR(1024),
    @Default VARCHAR(16),
    @GUID VARCHAR(36) OUTPUT
WITH
    EXEC AS CALLER
AS
BEGIN
    DECLARE @BaseCode INT = 50000
    DECLARE @ReturnCode INT
    DECLARE @Message VARCHAR(200)

    BEGIN TRY

		INSERT INTO [authz].[HOST_GROUPS]
        (
        [GUID],
        [Name],
        [Description],
        [Default],
        [CreateUser],
        [UpdateUser])
    VALUES
        (
            newid(),
            @Name,
            @Description,
            @Default,
            @SessionGUID,
            @SessionGUID);

		DECLARE @ID INT
		SELECT @ID = SCOPE_IDENTITY()
		
		SELECT @GUID = GUID
    FROM [authz].HOST_GROUPS [hg]
    WHERE [hg].ID = @ID
		    
		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [hg].GUID AS "guid",
        [hg].Name AS "name",
        [hg].[Default] AS "default",
        [hg].Description AS "description",
        FORMAT([hg].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
        [hg].CreateUser AS "createUser",
        FORMAT([hg].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
        [hg].UpdateUser AS "updateUser"
    FROM [authz].HOST_GROUPS [hg]
    WHERE [hg].ID = @ID
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
    
    SELECT @json

    END TRY
  
    BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
        THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'Create host group failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
    END CATCH
END
