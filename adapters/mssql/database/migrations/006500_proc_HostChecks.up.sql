CREATE PROCEDURE [auth].[HostChecks]
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @json NVARCHAR(max)
  SET @json = (
  SELECT 
  [h].Hostname AS "checkhost", [h].DefaultAccess AS "defaultAccess",
  (SELECT [c].Name AS "name",
          [c].Base AS "base",
          (SELECT [p].Path AS "path",
                  (SELECT [r].Method AS "method", 
                          [r].Description AS "Description", 
                          [r].Expr AS "expr" 
                   FROM [auth].[RULES] [r]
                   WHERE [r].PathID = [p].ID FOR JSON PATH) AS "rules"
           FROM [auth].[PATHS] [p]
           WHERE [p].CheckID = [c].ID FOR JSON PATH) AS "paths"
     FROM [auth].[HOST_CHECKS] [hc]
     INNER JOIN [auth].[CHECKS] [c] ON [hc].CheckID = [c].ID
     WHERE [hc].HostID = [h].ID FOR JSON PATH) AS "acl"
  FROM [auth].[HOSTS] [h]
  FOR JSON PATH)
  SELECT ISNULL(@json, '[]')
END;

