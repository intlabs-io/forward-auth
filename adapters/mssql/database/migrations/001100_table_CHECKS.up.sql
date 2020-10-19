CREATE TABLE [auth].[CHECKS] (
        [ID] [int] IDENTITY(1,1) NOT NULL,
        [Name] [varchar](80) NOT NULL,
        [Base] [varchar](256) NOT NULL,
        [Created] [datetime] NOT NULL,
        [CreateUser] [varchar](50) NOT NULL,
        [Updated] [datetime] NOT NULL,
        [UpdateUser] [varchar](50) NOT NULL,
  CONSTRAINT [PK_CHECKS] PRIMARY KEY CLUSTERED ([ID] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
  CONSTRAINT [UK_CHECKS_Name] UNIQUE NONCLUSTERED ([Name] ASC)
    WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY];
ALTER TABLE [auth].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_Created]  DEFAULT (getdate()) FOR [Created];
ALTER TABLE [auth].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_CreateUser]  DEFAULT ('ROOT') FOR [CreateUser];
ALTER TABLE [auth].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_Updated]  DEFAULT (getdate()) FOR [Updated];
ALTER TABLE [auth].[CHECKS] ADD  CONSTRAINT [DF_CHECKS_UpdateUser]  DEFAULT ('ROOT') FOR [UpdateUser];
