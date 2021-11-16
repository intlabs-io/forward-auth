ALTER PROCEDURE [authz].[GetTenantTokens]

AS
BEGIN

DECLARE @json NVARCHAR(max)

SET @json = '{' + (SELECT STRING_AGG('"' + [i].EPBCID + '": "' + [ic].ConfigValue + '"', N',')
FROM inst.SERVICE_TYPES [st]
INNER JOIN inst.INSTITUTION_SERVICES [is] ON [is].ServiceTypeID = [st].ID
INNER JOIN inst.INSTITUTIONS [i] ON [is].InstitutionID = [i].ID
INNER JOIN inst.SERVICE_CONFIGS [sc] ON [sc].ServiceTypeID = [st].ID
INNER JOIN inst.INSTITUTION_CONFIGS [ic] ON [ic].InstitutionID = [i].ID AND [ic].ServiceConfigID = [sc].ID
WHERE [st].Code = 'API' AND [is].IsEnabled = 1 AND [sc].ConfigKey = 'TOKEN') + '}'

SELECT JSON_QUERY(@json)

END
