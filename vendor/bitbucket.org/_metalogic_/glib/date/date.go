package date

import (
	"fmt"
	"strings"
	"time"

	"bitbucket.org/_metalogic_/log"
)

const (
	RFC3339Z   = "2006-01-02T15:04:05Z"
	RFC3339INT = "20060102150405"
)

var (
	tspecs = []string{"2006", "2006-01", "2006-01-02", time.RFC3339, RFC3339INT, RFC3339Z}
)

// Date is a custom date
type Date struct {
	time.Time
}

// UnmarshalJSON ...
func (d *Date) UnmarshalJSON(input []byte) error {
	if input == nil {
		return nil
	}
	strInput := string(input)
	strInput = strings.Trim(strInput, `"`)
	newTime, err := time.Parse("2006-01-02", strInput)
	if err != nil {
		return err
	}

	d.Time = newTime
	return nil
}

// DateTime converts Date to a time.Time
func (d *Date) DateTime() time.Time {
	return d.Time
}

// AgeAt gets the age of an entity at a certain time.
func AgeAt(birthdate time.Time, at time.Time) int {
	// Get the year number change since birth.
	years := at.Year() - birthdate.Year() // 2024-2020 = 4

	// If the date is before the date of birth, then not that many years have elapsed.
	birthday := getAdjustedBirthday(birthdate, at) // = 60
	if at.YearDay() < birthday {                   // 59 < 60
		years--
	}

	return years
}

// Age is shorthand for AgeAt(birthDate, time.Now()), and carries the same usage and limitations.
func Age(birthDate time.Time) int {
	return AgeAt(birthDate, time.Now())
}

// Gets the adjusted date of birth to work around leap year differences.
func getAdjustedBirthday(birthdate time.Time, at time.Time) int {
	birthday := birthdate.YearDay() // 1896-02-29 = 60
	atDay := at.YearDay()           // 1900-02-28 = 59
	if IsLeap(at) && !IsLeap(birthdate) && atDay >= 60 {
		return birthday + 1
	}
	return birthday
}

// IsLeap returns true if [date] is in a leap year.
func IsLeap(date time.Time) bool {
	year := date.Year()
	if year%400 == 0 {
		return true
	} else if year%100 == 0 {
		return false
	} else if year%4 == 0 {
		return true
	}
	return false
}

// Last returns the datetime for the last occurence of Month and Day [md]
func Last(md string) (t time.Time, err error) {

	now := time.Now()
	y := now.Year()

	ymd := fmt.Sprintf("%d-%s", y, md)

	// t, err := time.Parse(RFC3339INT, s)
	t, err = time.Parse("2006-Jan-02", ymd)
	if err != nil {
		log.Error(err)
		return t, err
	}

	if now.Before(t) {
		ymd = fmt.Sprintf("%d-%s", y-1, md)
		t, err = time.Parse("2006-Jan-02", ymd)
		if err != nil {
			log.Error(err)
			return t, err
		}
	}

	log.Debugf("parsed next as %v+", t)
	return t, nil
}

// accepts a single Mon-dd argument [md]
func Next(md string) (t time.Time, err error) {

	now := time.Now()
	y := now.Year()

	ymd := fmt.Sprintf("%d-%s", y, md)

	// t, err := time.Parse(RFC3339INT, s)
	t, err = time.Parse("2006-Jan-02", ymd)
	if err != nil {
		log.Error(err)
		return t, err
	}

	if now.After(t) {
		ymd = fmt.Sprintf("%d-%s", y+1, md)
		t, err = time.Parse("2006-Jan-02", ymd)
		if err != nil {
			log.Error(err)
			return t, err
		}
	}

	log.Debugf("parsed next as %v+", t)
	return t, nil
}
