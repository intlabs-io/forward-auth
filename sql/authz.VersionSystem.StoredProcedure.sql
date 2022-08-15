SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[VersionSystem]
@SessionGUID VARCHAR(36),
@Comment VARCHAR(256),
@Version INT OUTPUT
WITH EXEC AS CALLER
AS
BEGIN
    DECLARE @BaseCode INT = 50000
    DECLARE @ReturnCode INT
    DECLARE @Message VARCHAR(200)

    BEGIN TRY
    
    BEGIN TRANSACTION

		INSERT INTO [authz].[SYSTEMS] (
		  [Version],
			[Comment],
			[CreateUser],
			[UpdateUser])
		VALUES (
			NEXT VALUE FOR [authz].Version,
			@Comment,
			@SessionGUID,
			@SessionGUID);

		DECLARE @ID INT
		SELECT @ID = SCOPE_IDENTITY()
		
		SELECT @Version = Version FROM [authz].SYSTEMS [s] WHERE [s].ID = @ID
		
		COMMIT TRANSACTION
		    
		DECLARE @json NVARCHAR(max)
    SET @json = 
      (SELECT [s].Version AS "version", 
              [s].Comment AS "comment",
              FORMAT([s].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [s].CreateUser AS "createUser",
              FORMAT([s].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [s].UpdateUser AS "updateUser"
       FROM [authz].SYSTEMS [s]
       WHERE [s].ID = @ID
       FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
    
    SELECT @json

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
       SELECT @ErrorMessage = 'version system failed: ' + ERROR_MESSAGE();
       THROW 50000, @ErrorMessage, 1;
    END CATCH
END
GO
