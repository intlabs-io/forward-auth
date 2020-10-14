CREATE TABLE [auth].[PATHS] (
        [ID] [int] IDENTITY(1,1) NOT NULL,
	[CheckID] [int] NOT NULL,
        [Path] [varchar](1024) NOT NULL,
        [Created] [datetime] NOT NULL,
        [CreateUser] [varchar](50) NOT NULL,
        [Updated] [datetime] NOT NULL,
        [UpdateUser] [varchar](50) NOT NULL,
  CONSTRAINT [PK_PATHS] PRIMARY KEY CLUSTERED ([ID] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
  CONSTRAINT [UK_PATHS_CheckID_Path] UNIQUE NONCLUSTERED ([CheckID] ASC,[Path] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY];
ALTER TABLE [auth].[PATHS] ADD  CONSTRAINT [DF_PATHS_Created]  DEFAULT (getdate()) FOR [Created];
ALTER TABLE [auth].[PATHS] ADD  CONSTRAINT [DF_PATHS_CreateUser]  DEFAULT ('ROOT') FOR [CreateUser];
ALTER TABLE [auth].[PATHS] ADD  CONSTRAINT [DF_PATHS_Updated]  DEFAULT (getdate()) FOR [Updated];
ALTER TABLE [auth].[PATHS] ADD  CONSTRAINT [DF_PATHS_UpdateUser]  DEFAULT ('ROOT') FOR [UpdateUser];
ALTER TABLE [auth].[PATHS] WITH CHECK ADD CONSTRAINT [FK_PATHS_CheckID] FOREIGN KEY([CheckID])
REFERENCES [auth].[CHECKS] ([ID]);
ALTER TABLE [auth].[PATHS] CHECK CONSTRAINT [FK_PATHS_CheckID];