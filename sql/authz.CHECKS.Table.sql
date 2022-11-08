SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [authz].[CHECKS](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[GUID] [varchar](36) NOT NULL,
	[GroupID] [int] NOT NULL,
	[Name] [varchar](32) NOT NULL,
	[Description] [varchar](256) NULL,
	[Version] [int] NOT NULL,
	[Base] [varchar](128) NOT NULL,
	[Created] [datetime] NOT NULL,
	[CreateUser] [varchar](36) NOT NULL,
	[Updated] [datetime] NOT NULL,
	[UpdateUser] [varchar](36) NOT NULL
) ON [PRIMARY]
GO
ALTER TABLE [authz].[CHECKS] ADD PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [UK_CHECKS_Name_Version_Base] UNIQUE NONCLUSTERED 
(
	[GroupID] ASC,
	[Name] ASC,
	[Version] ASC,
	[Base] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
CREATE NONCLUSTERED INDEX [IX_authz_CHECKS_GUID] ON [authz].[CHECKS]
(
	[GUID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_GUID]  DEFAULT (newid()) FOR [GUID]
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_Version]  DEFAULT ((1)) FOR [Version]
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_Created]  DEFAULT (getdate()) FOR [Created]
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_CreateUser]  DEFAULT ('ROOT') FOR [CreateUser]
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_Updated]  DEFAULT (getdate()) FOR [Updated]
GO
ALTER TABLE [authz].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_UpdateUser]  DEFAULT ('ROOT') FOR [UpdateUser]
GO
ALTER TABLE [authz].[CHECKS]  WITH CHECK ADD  CONSTRAINT [FK_CHECKS_HostGroup] FOREIGN KEY([GroupID])
REFERENCES [authz].[HOST_GROUPS] ([ID])
GO
ALTER TABLE [authz].[CHECKS] CHECK CONSTRAINT [FK_CHECKS_HostGroup]
GO