CREATE TABLE [auth].[TENANT_BEARER_TOKENS](
	[ID] [int] IDENTITY(1,1) NOT NULL,
        [TenantID] [int] NOT NULL,   
	[Environment] [varchar](40) NOT NULL,
  	[Token] [varchar](255) NOT NULL,
	[Created] [datetime] NOT NULL,
        [CreateUser] [varchar](50) NOT NULL,
	[Updated] [datetime] NOT NULL,
	[UpdateUser] [varchar](50) NOT NULL,
  CONSTRAINT [PK_TENANT_BEARER_TOKENS] PRIMARY KEY CLUSTERED ([ID] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
  CONSTRAINT [UK_TENANT_BEARER_TOKENS_TenantID_Environment] UNIQUE NONCLUSTERED ([TenantID] ASC, [Environment] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY];
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] ADD CONSTRAINT [DF_TENANT_BEARER_TOKENS_Token]  DEFAULT (newid()) FOR [Token];
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] ADD CONSTRAINT [DF_TENANT_BEARER_TOKENS_Created]  DEFAULT (getdate()) FOR [Created];
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] ADD CONSTRAINT [DF_TENANT_BEARER_TOKENS_CreateUser]  DEFAULT ('ROOT') FOR [CreateUser];
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] ADD CONSTRAINT [DF_TENANT_BEARER_TOKENS_Updated]  DEFAULT (getdate()) FOR [Updated];
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] ADD CONSTRAINT [DF_TENANT_BEARER_TOKENS_UpdatedUser]  DEFAULT ('ROOT') FOR [UpdateUser];
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] WITH CHECK ADD CONSTRAINT [FK_TENANT_BEARER_TOKENS_TenantID] FOREIGN KEY([TenantID])
REFERENCES [auth].[TENANTS] ([ID]);
ALTER TABLE [auth].[TENANT_BEARER_TOKENS] CHECK CONSTRAINT [FK_TENANT_BEARER_TOKENS_TenantID];

-- add a few tenant bearer tokens for testing
INSERT INTO [auth].[TENANT_BEARER_TOKENS]
(TenantID, Environment, Token)
SELECT ID, 'DEV', '733acb21-3ca3-4f54-a9b0-1d219c659d1c' FROM [auth].[TENANTS] WHERE [name] = 'EPBC';
INSERT INTO [auth].[TENANT_BEARER_TOKENS]
(TenantID, Environment, Token)
SELECT ID, 'DEV', 'ce3b226d-330d-45b8-b45e-3cc9dc871a6c' FROM [auth].[TENANTS] WHERE [name] = 'SFU';
INSERT INTO [auth].[TENANT_BEARER_TOKENS]
(TenantID, Environment, Token)
SELECT ID, 'DEV', 'B46416DD-D27F-4A63-9983-94C878F7433D' FROM [auth].[TENANTS] WHERE [name] = 'SPUZZUM';
