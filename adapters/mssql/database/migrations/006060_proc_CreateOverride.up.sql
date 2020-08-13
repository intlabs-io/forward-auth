CREATE PROCEDURE [auth].[CreateOverride]
  @SessionGUID [varchar](50),
  @Hostname varchar(80),
  @Permission varchar(16)
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY

    DECLARE @HostID INT
    SELECT @HostID = ID from [auth].[HOSTS] WHERE Hostname = @Hostname
    IF @HostID IS NULL
    BEGIN
      SET @ReturnCode = @BaseCode + 404;
      SET @Message = 'host not found with hostname ' + @Hostname;
      THROW @ReturnCode, @Message, 1;
    END
    INSERT INTO [auth].[HOST_OVERRIDES]([HostID], [Permission], [CreateUser], [UpdateUser])
    VALUES (@HostID, @Permission, @SessionGUID, @SessionGUID)

    SELECT SCOPE_IDENTITY()

  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'create host override failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

