package timeutil

import "time"

// SystemClock provides the wall-clock implementation for Clock interfaces.
type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}
