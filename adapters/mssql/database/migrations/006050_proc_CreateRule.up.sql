CREATE PROCEDURE [auth].[CreateRule]
  @SessionGUID [varchar](50),
  @PathID int,
  @Method [varchar](16),
  @Description [varchar](1024),
  @Expr [varchar](2048)
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @BaseCode INT = 50000
  DECLARE @ReturnCode INT
  DECLARE @Message VARCHAR(200)

  BEGIN TRY

    INSERT INTO [auth].[RULES]([PathID], [Method], [Description], [Expr], [CreateUser], [UpdateUser])
    VALUES (@PathID, @Method, @Description, @Expr, @SessionGUID, @SessionGUID)

    SELECT SCOPE_IDENTITY()

  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'create rule failed: ' + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
  END CATCH
END;

