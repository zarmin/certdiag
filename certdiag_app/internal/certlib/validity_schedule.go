package certlib

import "time"

// leafValiditySchedule is the maximum validity of a publicly trusted TLS
// server certificate, by issuance date, from the CA/Browser Forum Baseline
// Requirements. Source: BR section 6.3.2 and ballot SC-081v3
// (https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/),
// last checked 2026-09-07. Refresh when the Forum votes a new schedule; the
// release checklist lists this file.
var leafValiditySchedule = []struct {
	from time.Time
	days int
}{
	{time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC), 825},
	{time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC), 398},
	{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
	{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
	{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
}

// LeafValidityLimit returns the longest validity, in days, a publicly trusted
// TLS leaf issued at notBefore may have, and the date that limit took effect.
func LeafValidityLimit(notBefore time.Time) (days int, since time.Time) {
	days, since = leafValiditySchedule[0].days, time.Time{}
	for _, entry := range leafValiditySchedule {
		if !notBefore.Before(entry.from) {
			days, since = entry.days, entry.from
		}
	}
	return days, since
}
