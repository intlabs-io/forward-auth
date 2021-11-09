package mssql

type Stats struct {
	MaxOpenConnections int
	OpenConnections int
	InUse int
	Idle int
	WaitCount int
	WaitDuration int
	MaxIdleClosed int
	MaxLifetimeClosed int
}

