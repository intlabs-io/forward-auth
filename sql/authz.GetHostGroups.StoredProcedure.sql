SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [authz].[GetHostGroups]
AS 
BEGIN 
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [hg].GUID AS "guid", 
              [hg].Name AS "name",
              [hg].[Default] AS "default",
              [hg].Description AS "description",
              JSON_QUERY([authz].Hostnames([hg].ID)) AS "hosts",
              FORMAT([hg].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [hg].CreateUser AS "createUser",
              FORMAT([hg].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [hg].UpdateUser AS "updateUser"
       FROM [authz].HOST_GROUPS [hg]
       FOR JSON PATH, INCLUDE_NULL_VALUES)
       
    SELECT ISNULL(@json, '[]')
END
GO
