SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [authz].[HOSTS](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[GUID] [varchar](36) NOT NULL,
	[GroupID] [int] NOT NULL,
	[Hostname] [varchar](256) NOT NULL,
	[Created] [datetime] NOT NULL,
	[CreateUser] [varchar](36) NOT NULL,
	[Updated] [datetime] NOT NULL,
	[UpdateUser] [varchar](36) NOT NULL
) ON [PRIMARY]
GO
ALTER TABLE [authz].[HOSTS] ADD PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
ALTER TABLE [authz].[HOSTS] ADD  CONSTRAINT [UK_HOSTS_Hostname] UNIQUE NONCLUSTERED 
(
	[Hostname] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
CREATE NONCLUSTERED INDEX [IX_authz_HOSTS_GUID] ON [authz].[HOSTS]
(
	[GUID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
ALTER TABLE [authz].[HOSTS] ADD  CONSTRAINT [DF_HOSTS_GUID]  DEFAULT (newid()) FOR [GUID]
GO
ALTER TABLE [authz].[HOSTS] ADD  CONSTRAINT [DF_HOSTS_Created]  DEFAULT (getdate()) FOR [Created]
GO
ALTER TABLE [authz].[HOSTS] ADD  CONSTRAINT [DF_HOSTS_CreateUser]  DEFAULT ('ROOT') FOR [CreateUser]
GO
ALTER TABLE [authz].[HOSTS] ADD  CONSTRAINT [DF_HOSTS_Updated]  DEFAULT (getdate()) FOR [Updated]
GO
ALTER TABLE [authz].[HOSTS] ADD  CONSTRAINT [DF_HOSTS_UpdateUser]  DEFAULT ('ROOT') FOR [UpdateUser]
GO
ALTER TABLE [authz].[HOSTS]  WITH CHECK ADD  CONSTRAINT [FK_HOSTS_Group] FOREIGN KEY([GroupID])
REFERENCES [authz].[HOST_GROUPS] ([ID])
GO
ALTER TABLE [authz].[HOSTS] CHECK CONSTRAINT [FK_HOSTS_Group]
GO
