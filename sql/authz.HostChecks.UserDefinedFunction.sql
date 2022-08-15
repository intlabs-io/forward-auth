SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [authz].[HostChecks](@GroupID INT)
RETURNS NVARCHAR(max)
AS 
BEGIN 
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT [c].Name AS "name",
              [c].Base AS "base",
              JSON_QUERY([authz].CheckPaths([c].ID)) AS "paths"
       FROM [authz].CHECKS [c]
       WHERE [c].GroupID = @GroupID
       FOR JSON PATH, INCLUDE_NULL_VALUES)
       
    RETURN ISNULL(@json, '[]')
END
GO
