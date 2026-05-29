package collector

import "time"

// msToDate converts a unix-milliseconds value to a local date string.
func msToDate(ms int64) string {
	return time.UnixMilli(ms).Local().Format("2006-01-02")
}
