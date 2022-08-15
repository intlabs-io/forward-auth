SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [authz].[Hostnames](@GroupID INT)
RETURNS NVARCHAR(max)
AS 
BEGIN 
    DECLARE @json NVARCHAR(max);
    
    SET @json = 
      (SELECT '[' + STRING_AGG(CONVERT(NVARCHAR(max), '"' + [h].Hostname + '"'), ',') + ']'
       FROM [authz].HOSTS [h]
       WHERE [h].GroupID = @GroupID)
       
    RETURN @json
END
GO
