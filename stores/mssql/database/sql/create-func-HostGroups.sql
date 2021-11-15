ALTER FUNCTION [authz].[HostGroups]()
RETURNS NVARCHAR(max)
AS 
BEGIN
  DECLARE @json NVARCHAR(max);

  SET @json = 
      (SELECT [hg].GUID AS "guid",
    [hg].Name AS "name",
    [hg].[Default] AS "default",
    [hg].Description AS "description",
    JSON_QUERY([authz].Hostnames([hg].ID)) AS "hosts",
    JSON_QUERY([authz].HostChecks([hg].ID)) AS "checks",
    [hg].Created AS "created",
    [hg].CreateUser AS "createUser",
    [hg].Updated AS "updated",
    [hg].UpdateUser AS "updateUser"
  FROM [authz].HOST_GROUPS [hg]
  FOR JSON PATH, INCLUDE_NULL_VALUES)

  RETURN ISNULL(@json, '[]')
END

