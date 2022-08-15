SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [authz].[ChecksJSON](@GroupID INT)
RETURNS NVARCHAR(max)
AS 
BEGIN 
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [ch].GUID AS "guid",
              [ch].Name AS "name",
              [ch].Description AS "description",
              [ch].Version AS "version",
              [ch].Base AS "base",
              FORMAT([ch].Created,'yyyy-MM-ddTHH:mm:ssZ') AS "created",
              [ch].CreateUser AS "createUser",
              FORMAT([ch].Updated,'yyyy-MM-ddTHH:mm:ssZ') AS "updated",
              [ch].UpdateUser AS "updateUser"
       FROM [authz].CHECKS [ch]
       WHERE [ch].GroupID = @GroupID
       FOR JSON PATH, INCLUDE_NULL_VALUES)
       
    RETURN ISNULL(@json, '[]')
END
GO
