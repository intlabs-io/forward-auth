CREATE PROCEDURE [auth].[CreatePath]
  @SessionGUID [varchar](50),
  @CheckID int,
  @Path [varchar](1024)
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY

    INSERT INTO [auth].[PATHS]([CheckID], [Path], [CreateUser], [UpdateUser])
    VALUES (@CheckID, @Path, @SessionGUID, @SessionGUID)

    SELECT SCOPE_IDENTITY()

  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'create path failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

