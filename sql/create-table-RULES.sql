SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [authz].[RULES]
(
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[GUID] [varchar](36) NOT NULL,
	[HostGroupID] [int] NOT NULL,
	[Name] [varchar](32) NOT NULL,
	[BaseURI] [varchar](48) NOT NULL,
	[Paths] [nvarchar](max) NOT NULL,
	[Created] [datetime] NOT NULL,
	[CreateUser] [varchar](36) NOT NULL,
	[Updated] [datetime] NOT NULL,
	[UpdateUser] [varchar](36) NOT NULL,
) ON [PRIMARY]
GO
ALTER TABLE [authz].[RULES] ADD PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
ALTER TABLE [authz].[RULES] ADD  DEFAULT (newid()) FOR [GUID]
GO
ALTER TABLE [authz].[RULES] ADD  DEFAULT (getdate()) FOR [Created]
GO
ALTER TABLE [authz].[RULES] ADD  DEFAULT ('ROOT') FOR [CreateUser]
GO
ALTER TABLE [authz].[RULES] ADD  DEFAULT (getdate()) FOR [Updated]
GO
ALTER TABLE [authz].[RULES] ADD  DEFAULT ('ROOT') FOR [UpdateUser]
GO

ALTER TABLE [authz].[RULES] WITH CHECK ADD CONSTRAINT [RULES_HostGroup_FK] FOREIGN KEY([HostGroupID])
REFERENCES [authz].[HOST_GROUPS] ([ID])
GO

ALTER TABLE [authz].[RULES] WITH CHECK ADD CONSTRAINT [RULES_Path_IsJSON] CHECK (ISJSON(Paths) > 0)
GO