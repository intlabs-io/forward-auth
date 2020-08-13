CREATE PROCEDURE [auth].[CreateCheck]
  @SessionGUID [varchar](50),
  @Name varchar(80),
  @Base varchar(256)
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY

    INSERT INTO [auth].[CHECKS]([Name], [Base], [CreateUser], [UpdateUser])
    VALUES (@Name, @Base, @SessionGUID, @SessionGUID)

    SELECT SCOPE_IDENTITY()

  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'create check failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

