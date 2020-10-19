CREATE PROCEDURE [auth].[HostChecks]
WITH EXEC AS CALLER
AS
BEGIN
  DECLARE @json NVARCHAR(max)
  SET @json = (
  SELECT [hc].DefaultAccess AS "defaultAccess",
      (SELECT [h].Hostname AS "hostname" FROM [auth].[HOSTS] [h] WHERE [h].ID = [hc].HostID FOR JSON PATH) AS "hosts",
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
      FROM [auth].[CHECKS] [c]
      WHERE [c].ID = [hc].CheckID FOR JSON PATH) AS "acl"
  FROM [auth].[HOST_CHECKS] [hc]
  FOR JSON PATH)
  SELECT ISNULL(@json, '[]')
END;
