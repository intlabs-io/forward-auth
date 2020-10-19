CREATE FUNCTION
[dbo].[RawJsonArray](@json nvarchar(max), @key nvarchar(400)) returns nvarchar(max)
AS BEGIN
       declare @new nvarchar(max) = replace(@json, CONCAT('},{"', @key,'":'),',')
       return '[' + substring(@new, 1 + (LEN(@key)+5), LEN(@new) -2 - (LEN(@key)+5)) + ']'
END;
