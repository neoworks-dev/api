package database

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// localDateTimeLayout is the jsCalendar LocalDateTime form (no zone offset).
const localDateTimeLayout = "2006-01-02T15:04:05"

// deriveBounds computes the absolute UTC [start, end) for the internal index
// columns from a jsCalendar start (LocalDateTime), duration (ISO-8601) and IANA
// time zone (nil/empty = UTC). A nil/empty duration yields a zero-length span.
func deriveBounds(start string, duration, timeZone *string) (time.Time, time.Time, error) {
	loc := time.UTC
	if timeZone != nil && *timeZone != "" {
		l, err := time.LoadLocation(*timeZone)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid time_zone %q: %w", *timeZone, err)
		}
		loc = l
	}

	// Accept either a bare LocalDateTime or a full RFC3339 instant (the client may
	// still send absolute times during the transition).
	startLocal, err := time.ParseInLocation(localDateTimeLayout, strings.TrimSuffix(start, "Z"), loc)
	if err != nil {
		if t, e2 := time.Parse(time.RFC3339, start); e2 == nil {
			startLocal = t
		} else {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start %q: %w", start, err)
		}
	}
	startUTC := startLocal.UTC()

	if duration == nil || *duration == "" {
		return startUTC, startUTC, nil
	}
	years, months, days, clock, err := parseISODuration(*duration)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	end := startLocal.AddDate(years, months, days).Add(clock).UTC()
	return startUTC, end, nil
}

// parseISODuration parses an ISO-8601 duration (PnYnMnWnDTnHnMnS) into calendar
// components plus a clock duration. Fractional values are not supported.
func parseISODuration(s string) (years, months, days int, clock time.Duration, err error) {
	negative := false
	if strings.HasPrefix(s, "-") {
		negative = true
		s = s[1:]
	}
	if !strings.HasPrefix(s, "P") {
		return 0, 0, 0, 0, fmt.Errorf("invalid duration %q: must start with P", s)
	}
	s = s[1:]

	datePart, timePart, hasTime := strings.Cut(s, "T")

	parse := func(part string, units map[byte]func(int)) error {
		num := ""
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c >= '0' && c <= '9' {
				num += string(c)
				continue
			}
			apply, ok := units[c]
			if !ok {
				return fmt.Errorf("invalid duration unit %q in %q", string(c), s)
			}
			if num == "" {
				return fmt.Errorf("missing number before %q in %q", string(c), s)
			}
			v, convErr := strconv.Atoi(num)
			if convErr != nil {
				return convErr
			}
			apply(v)
			num = ""
		}
		if num != "" {
			return fmt.Errorf("dangling number %q in %q", num, s)
		}
		return nil
	}

	if err = parse(datePart, map[byte]func(int){
		'Y': func(v int) { years = v },
		'M': func(v int) { months = v },
		'W': func(v int) { days += v * 7 },
		'D': func(v int) { days += v },
	}); err != nil {
		return 0, 0, 0, 0, err
	}
	if hasTime {
		if err = parse(timePart, map[byte]func(int){
			'H': func(v int) { clock += time.Duration(v) * time.Hour },
			'M': func(v int) { clock += time.Duration(v) * time.Minute },
			'S': func(v int) { clock += time.Duration(v) * time.Second },
		}); err != nil {
			return 0, 0, 0, 0, err
		}
	}

	if negative {
		years, months, days, clock = -years, -months, -days, -clock
	}
	return years, months, days, clock, nil
}
