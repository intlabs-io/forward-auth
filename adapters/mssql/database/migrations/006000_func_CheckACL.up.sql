CREATE FUNCTION [auth].[CheckACL] (@ID INT)
RETURNS NVARCHAR(MAX)
AS
BEGIN
    RETURN (
      SELECT [c].Name AS "name",
             [c].Base AS "base"
     FROM [auth].[HOSTS] [h]
     INNER JOIN [auth].[HOST_CHECKS] [hc] ON [hc].HostID = [h].ID
     INNER JOIN [auth].[CHECKS] [c] ON [hc].CheckID = [c].ID
     WHERE [h].ID = @ID
     FOR JSON PATH)
END
