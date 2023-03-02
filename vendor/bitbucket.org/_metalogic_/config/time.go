package config

import (
	"fmt"
	"strings"
	"time"
)

var (
	formats = []string{
		"2006", "2006-01", "2006-01-02", "2006-01-02 15", "2006-01-02 15:04", "2006-01-02 15:04:05", "15:04", "Monday", "Mon"}
	daysOfWeek = map[string]time.Weekday{
		"sunday":    time.Sunday,
		"monday":    time.Monday,
		"tuesday":   time.Tuesday,
		"wednesday": time.Wednesday,
		"thursday":  time.Thursday,
		"friday":    time.Friday,
		"saturday":  time.Saturday,
		"sun":       time.Sunday,
		"mon":       time.Monday,
		"tue":       time.Tuesday,
		"wed":       time.Wednesday,
		"thu":       time.Thursday,
		"fri":       time.Friday,
		"sat":       time.Saturday,
	}
)

// GetDatetime attempts to parse a partial time string against formats into time.Time
func GetDatetime(tstr string) (t time.Time, err error) {
	return getDatetime(tstr, nil)
}

// GetDatetimeInLocation attempts to parse a partial time string against formats into time.Time in a given time.Location
func GetDatetimeInLocation(tstr string, location *time.Location) (t time.Time, err error) {
	return getDatetime(tstr, location)
}

func getDatetime(tstr string, location *time.Location) (t time.Time, err error) {
	var now time.Time
	weekday, err := GetWeekday(tstr)
	if err == nil {
		t := GetLast(weekday)
		return GetDatetime(t.Format("2006-01-02 15:04:05"))
	}
	if location == nil {
		now = time.Now().UTC()
	} else {
		now = time.Now().In(location)
	}

	y := now.Format("2006")
	m := now.Format("01")
	datetimes := []string{tstr, fmt.Sprintf("%s-%s", y, tstr), fmt.Sprintf("%s-%s-%s", y, m, tstr)}
	for _, dt := range datetimes {
		for _, format := range formats {
			if location == nil {
				t, err = time.Parse(format, dt)
			} else {
				t, err = time.ParseInLocation(format, dt, location)
			}
			if err == nil {
				return t, err
			}
		}
	}
	return t, err
}

// GetLast returns time at midnight of the most recent given weekday
func GetLast(day time.Weekday) time.Time {
	now := time.Now().UTC()
	today := now.Weekday()
	ago := time.Duration(today - day)
	if ago >= 0 {
		ago = -ago
	} else {
		ago = (-7 - ago)
	}
	last := now.Add(time.Hour * (24 * ago))
	return BoD(last)
}

// BoD returns returns the time at midnight of the given time
func BoD(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.UTC().Location())
}

// GetWeekday returns a time.Weekday parsed from a given day string
func GetWeekday(day string) (time.Weekday, error) {
	var weekday time.Weekday
	day = strings.ToLower(day)
	if weekday, ok := daysOfWeek[day]; ok {
		return weekday, nil
	}
	return weekday, fmt.Errorf("invalid day: '%s'", day)
}
