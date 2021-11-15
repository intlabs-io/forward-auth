--
-- GetAccessControlSystem returns a JSON response representing access control
-- rules for a collection of hosts and the URI space they expose
--
-- Project Usages
--   metalogic/forward-auth
-- Database Dependencies:
--    EXEC [util].GetObjectDependencies('authz.GetAccessControlSystem')
--
-- References
--   authz.HOST_GROUPS  USER_TABLE
--   authz.HOSTS        USER_TABLE
--   authz.CHECKS       USER_TABLE
--   authz.PATHS        USER_TABLE

ALTER PROCEDURE [authz].[GetAccessControlSystem]
WITH
    EXEC AS CALLER
AS
BEGIN
    DECLARE @BaseCode INT = 50000
    DECLARE @ReturnCode INT
    DECLARE @Message VARCHAR(200)

    DECLARE @Version VARCHAR(10) = 'v1.0'

    BEGIN TRY

    -- Note: the use of @json below is to work around a truncation issue with JSON results:
    -- https://stackoverflow.com/questions/51087037/sql-server-json-truncated-even-when-using-nvarcharmax
    
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT JSON_QUERY('{}') AS "overrides",
        JSON_QUERY(authz.HostGroups()) AS "hostGroups"
    FOR JSON PATH, INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER)
 
    SELECT @json
  END TRY
  
  BEGIN CATCH
    IF ERROR_NUMBER() > 50000
    BEGIN
      THROW;
    END
    DECLARE @ErrorMessage VARCHAR(400)
    SELECT @ErrorMessage = 'Get access control system failed '  + ERROR_MESSAGE();
    THROW 50000, @ErrorMessage, 1;
    END CATCH
END

