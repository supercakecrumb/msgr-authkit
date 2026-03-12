package cloneutil

import "time"

// TimePtr returns a deep copy of a *time.Time.
func TimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	t := *in
	return &t
}

// StringMap returns a deep copy of map[string]string.
func StringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
