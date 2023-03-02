package sql

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"
)

// IfNullBool invalidates a sql.NullBool if incoming bool is equal to nullValue
func IfNullBool(t, nullValue bool) sql.NullBool {
	if t == nullValue {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: t, Valid: true}
}

// IfNullBoolRef invalidates a sql.NullBool if incoming *bool is nil
func IfNullBoolRef(t *bool) sql.NullBool {
	if t == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *t, Valid: true}
}

// IfNullFloat validates a sql.NullFloat64 if f is equal to nullValue, invalidates if it does not
func IfNullFloat(f, nullValue float64) sql.NullFloat64 {
	if f == nullValue {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: float64(f), Valid: true}
}

// IfNullInt validates a sql.NullInt64 if i is equal to nullValue, invalidates if it does not
func IfNullInt(i, nullValue int) sql.NullInt64 {
	if i == nullValue {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(i), Valid: true}
}

// IfNullInt16 validates a sql.NullInt32 if i is equal to nullValue, invalidates if it does not
func IfNullInt16(i, nullValue int16) sql.NullInt16 {
	if i == nullValue {
		return sql.NullInt16{}
	}
	return sql.NullInt16{Int16: int16(i), Valid: true}
}

// IfNullInt32 validates a sql.NullInt32 if i is equal to nullValue, invalidates if it does not
func IfNullInt32(i, nullValue int32) sql.NullInt32 {
	if i == nullValue {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: int32(i), Valid: true}
}

// IfNullInt64 validates a sql.NullInt64 if i is equal to nullValue, invalidates if it does not
func IfNullInt64(i, nullValue int64) sql.NullInt64 {
	if i == nullValue {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(i), Valid: true}
}

// IfNullIntRef validates a sql.NullInt64 if i is nil or its reference is equal to nullValue, invalidates if it does not
func IfNullIntRef(i *int, nullValue int) sql.NullInt64 {
	if i == nil || *i == nullValue {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*i), Valid: true}
}

// IfNullIntString validates a string as an int64, invalidates if it does not
func IfNullIntString(s string) sql.NullInt64 {
	i, err := strconv.Atoi(s)
	return sql.NullInt64{Int64: int64(i), Valid: err == nil}
}

// IfNullString invalidates a sql.NullString if empty, validates if not empty
func IfNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// ToNullString invalidates a sql.NullString if empty, validates if not empty
func ToNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// IfNullTime invalidates a sql.NullTime if it is sero value, validates if not zero
func IfNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// ToNullTime invalidates a sql.NullTime if empty, validates if not empty
func ToNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// Stats returns service statistics
func DBStats(db *sql.DB) string {
	dbstats := db.Stats()
	return fmt.Sprintf(`{"MaxOpenConnections": %d, "OpenConnections" : %d, "InUse": %d, "Idle": %d, "WaitCount": %d, "WaitDuration": %d, "MaxIdleClosed": %d, "MaxLifetimeClosed": %d}`,
		dbstats.MaxOpenConnections,
		dbstats.OpenConnections,
		dbstats.InUse,
		dbstats.Idle,
		dbstats.WaitCount,
		dbstats.WaitDuration,
		dbstats.MaxIdleClosed,
		dbstats.MaxLifetimeClosed)
}

func Version(db *sql.DB, driverName string) (version string, err error) {
	switch driverName {
	case "postgres":
		err = db.QueryRow("SELECT version()").Scan(&version)
	case "sqlserver":
		err = db.QueryRow("SELECT @@VERSION").Scan(&version)
	default:
		err = fmt.Errorf("driverName %s not supported", driverName)
	}
	if err != nil {
		return version, err
	}
	return version, nil
}
