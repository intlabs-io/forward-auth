CREATE TABLE [auth].[RULES] (
        [ID] [int] IDENTITY(1,1) NOT NULL,
	[PathID] [int] NOT NULL,
        [Method] [varchar](16) NOT NULL,
        [Description] [varchar](1024) NOT NULL,
        [Expr] [varchar](2048) NOT NULL,
        [Created] [datetime] NOT NULL,
        [CreateUser] [varchar](50) NOT NULL,
        [Updated] [datetime] NOT NULL,
        [UpdateUser] [varchar](50) NOT NULL,
  CONSTRAINT [PK_RULES] PRIMARY KEY CLUSTERED ([ID] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
  CONSTRAINT [UK_RULES_PathID_Method] UNIQUE NONCLUSTERED ([PathID] ASC,[Method] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY];
ALTER TABLE [auth].[RULES] ADD  CONSTRAINT [DF_RULES_Description]  DEFAULT ('TODO') FOR [Description];
ALTER TABLE [auth].[RULES] ADD  CONSTRAINT [DF_RULES_Expr]  DEFAULT ('false') FOR [Expr];
ALTER TABLE [auth].[RULES] ADD  CONSTRAINT [DF_RULES_Created]  DEFAULT (getdate()) FOR [Created];
ALTER TABLE [auth].[RULES] ADD  CONSTRAINT [DF_RULES_CreateUser]  DEFAULT ('ROOT') FOR [CreateUser];
ALTER TABLE [auth].[RULES] ADD  CONSTRAINT [DF_RULES_Updated]  DEFAULT (getdate()) FOR [Updated];
ALTER TABLE [auth].[RULES] ADD  CONSTRAINT [DF_RULES_UpdateUser]  DEFAULT ('ROOT') FOR [UpdateUser];
ALTER TABLE [auth].[RULES] WITH CHECK ADD CONSTRAINT [FK_RULES_PathID] FOREIGN KEY([PathID])
REFERENCES [auth].[PATHS] ([ID]);
ALTER TABLE [auth].[RULES] CHECK CONSTRAINT [FK_RULES_PathID];
ALTER TABLE [auth].[RULES] ADD CONSTRAINT [CHK_RULES_Method] CHECK ([Method] = 'GET' OR [Method] = 'HEAD' OR [Method] = 'POST' OR [Method] = 'PUT' OR [Method] = 'DELETE');
