CREATE PROCEDURE [auth].[CreateHostCheck]
  @SessionGUID [varchar](50),
  @HostID int,
  @CheckID int
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY

    INSERT INTO [auth].[HOST_CHECKS]([HostID], [CheckID], [CreateUser], [UpdateUser])
    VALUES (@HostID, @CheckID, @SessionGUID, @SessionGUID)

    SELECT SCOPE_IDENTITY()

  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'create host check failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

