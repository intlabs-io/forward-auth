CREATE PROCEDURE [auth].[CreateHost]
  @SessionGUID [varchar](50),
  @Hostname varchar(40),
  @DefaultAccess varchar(20)
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY

    INSERT INTO [auth].[HOSTS]([Hostname],[DefaultAccess],[CreateUser],[UpdateUser])
    VALUES (@Hostname,@DefaultAccess,@SessionGUID,@SessionGUID)

    SELECT SCOPE_IDENTITY()

  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'create host failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

