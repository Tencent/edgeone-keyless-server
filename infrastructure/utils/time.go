package utils

import (
	"fmt"
	"time"

	"edgeone-keyless-server/infrastructure/constant"
)

// TimeFormat time format
func TimeFormat(now int64) string {
	if now < 0 {
		return ""
	}
	t := time.Unix(now, 0)
	// Create China timezone (UTC+8)
	location, err := time.LoadLocation(constant.TIME_LOCATION)
	if err != nil {
		fmt.Println("Error loading location:", err)
		return ""
	}
	// Convert time to China timezone
	chinaTime := t.In(location)
	return chinaTime.Format(constant.TIME_FORMAT)
}
