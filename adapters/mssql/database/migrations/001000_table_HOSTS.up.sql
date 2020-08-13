CREATE TABLE [auth].[HOSTS] (
        [ID] [int] IDENTITY(1,1) NOT NULL,
        [Hostname] [varchar](200) NOT NULL,
        [DefaultAccess] [varchar](20) NOT NULL,
        [Created] [datetime] NOT NULL,
        [CreateUser] [varchar](50) NOT NULL,
        [Updated] [datetime] NOT NULL,
        [UpdateUser] [varchar](50) NOT NULL,
  CONSTRAINT [PK_HOSTS] PRIMARY KEY CLUSTERED ([ID] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
  CONSTRAINT [UK_HOSTS_Hostname] UNIQUE NONCLUSTERED ([Hostname] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY];
ALTER TABLE [auth].[HOSTS] ADD CONSTRAINT [DF_HOSTS_DefaultAccess] DEFAULT ('deny') FOR [DefaultAccess];
ALTER TABLE [auth].[HOSTS] ADD CONSTRAINT [DF_HOSTS_Created] DEFAULT (getdate()) FOR [Created];
ALTER TABLE [auth].[HOSTS] ADD CONSTRAINT [DF_HOSTS_CreateUser] DEFAULT ('ROOT') FOR [CreateUser];
ALTER TABLE [auth].[HOSTS] ADD CONSTRAINT [DF_HOSTS_Updated] DEFAULT (getdate()) FOR [Updated];
ALTER TABLE [auth].[HOSTS] ADD CONSTRAINT [DF_HOSTS_UpdateUser] DEFAULT ('ROOT') FOR [UpdateUser];
ALTER TABLE [auth].[HOSTS] ADD CONSTRAINT [CHK_HOSTS_DefaultAccess] CHECK ([DefaultAccess] = 'allow' OR [DefaultAccess] = 'deny');
