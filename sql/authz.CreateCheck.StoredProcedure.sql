SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[CreateCheck]
@SessionGUID VARCHAR(36),
@GroupGUID VARCHAR(36),
@Name VARCHAR(32),
@Description VARCHAR(256),
@Version INT,
@Base VARCHAR(128),
@GUID VARCHAR(36) OUTPUT
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

    IF @Version IS NULL
    BEGIN
  		INSERT INTO [authz].[CHECKS] (
	  	  [GUID],
	  	  [GroupID],
	  		[Name],
	  		[Description],
	  		[Base],
	  		[CreateUser],
	  		[UpdateUser])
	  	VALUES (
		  	newid(),
		    @GroupID,
		  	@Name,
		  	@Description,
		  	@Base,
		  	@SessionGUID,
		  	@SessionGUID);
	  END
	  ELSE
	  BEGIN
	  	INSERT INTO [authz].[CHECKS] (
	  	  [GUID],
	  	  [GroupID],
	  		[Name],
	  		[Description],
	  		[Version],
	  		[Base],
	  		[CreateUser],
	  		[UpdateUser])
	  	VALUES (
	  		newid(),
	  	  @GroupID,
	  		@Name,
	  		@Description,
	  		@Version,
		  	@Base,
		  	@SessionGUID,
		  	@SessionGUID);	  
	  END

		DECLARE @ID INT
		SELECT @ID = SCOPE_IDENTITY()
		
		SELECT @GUID = GUID FROM [authz].[CHECKS] WHERE ID = @ID
		
		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [c].[GUID] AS "guid", 
              [c].[Name] AS "name",
              [c].[Description] AS "description",
              [c].[Version] AS "version",
              [c].[Base] AS "base",
              FORMAT([c].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [c].CreateUser AS "createUser",
              FORMAT([c].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [c].UpdateUser AS "updateUser"
       FROM [authz].CHECKS [c]
       WHERE [c].ID = @ID
       FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
       
    SELECT @json

    END TRY
  
    BEGIN CATCH
        IF ERROR_NUMBER() > 50000
        BEGIN
            THROW;
        END
        DECLARE @ErrorMessage VARCHAR(400)
        SELECT @ErrorMessage = 'Create host check failed: ' + ERROR_MESSAGE();
        THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
