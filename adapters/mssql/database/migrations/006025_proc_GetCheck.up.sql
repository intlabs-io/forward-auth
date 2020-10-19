CREATE PROCEDURE [auth].[GetCheck]
  @Name varchar(80),
  @Base varchar(256)
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY
    SELECT ID FROM [auth].[CHECKS] WHERE [Name] = @Name AND [Base] = @Base
  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'get check failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

