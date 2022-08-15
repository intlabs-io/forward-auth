SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [authz].[HostsJSON](@GroupID INT)
RETURNS NVARCHAR(max)
AS 
BEGIN 
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [h].GUID AS "guid",
              [h].Hostname AS "hostname",
              FORMAT([h].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [h].CreateUser AS "createUser",
              FORMAT([h].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [h].UpdateUser AS "updateUser"
       FROM [authz].HOSTS [h]
       WHERE [h].GroupID = @GroupID
       FOR JSON PATH, INCLUDE_NULL_VALUES)
       
    RETURN ISNULL(@json, '[]')
END
GO
