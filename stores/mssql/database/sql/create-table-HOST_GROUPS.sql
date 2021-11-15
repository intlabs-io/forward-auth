SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

DROP TABLE IF EXISTS [authz].[HOST_GROUPS]
GO

CREATE TABLE [authz].[HOST_GROUPS]
(
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[GUID] [varchar](36) NOT NULL,
	[Name] [varchar](32) NOT NULL,
	[Description] [varchar](1024) NULL,
	[Default] [varchar](16) NOT NULL,
	[Created] [datetime] NOT NULL,
	[CreateUser] [varchar](36) NOT NULL,
	[Updated] [datetime] NOT NULL,
	[UpdateUser] [varchar](36) NOT NULL,
) ON [PRIMARY]
GO

ALTER TABLE [authz].[HOST_GROUPS] ADD PRIMARY KEY CLUSTERED ([ID] ASC)
WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO

ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT [DF_HOST_GROUPS_GUID] DEFAULT (newid()) FOR [GUID]
GO
ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT [DF_HOST_GROUPS_Default] DEFAULT ('deny') FOR [Default]
GO
ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT [DF_HOST_GROUPS_Created] DEFAULT (getdate()) FOR [Created]
GO
ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT [DF_HOST_GROUPS_CreateUser] DEFAULT ('ROOT') FOR [CreateUser]
GO
ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT [DF_HOST_GROUPS_Updated] DEFAULT (getdate()) FOR [Updated]
GO
ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT [DF_HOST_GROUPS_UpdateUser] DEFAULT ('ROOT') FOR [UpdateUser]
GO

ALTER TABLE [authz].[HOST_GROUPS] ADD CONSTRAINT UK_HOST_GROUPS_Name UNIQUE ('Name')
GO

