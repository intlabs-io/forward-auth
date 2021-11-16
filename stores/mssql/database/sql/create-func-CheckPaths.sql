ALTER FUNCTION [authz].[CheckPaths](@CheckID INT)
RETURNS NVARCHAR(max)
AS 
BEGIN
  DECLARE @json NVARCHAR(max);

  SET @json = 
      (SELECT [p].[GUID] AS "guid",
    [p].[Path] AS "path",
    JSON_QUERY([p].[Rules]) AS "rules"
  FROM [authz].PATHS [p]
  WHERE [p].CheckID = @CheckID
  FOR JSON PATH, INCLUDE_NULL_VALUES)

  RETURN @json
END

