package utils

import (
	"fmt"
	"time"

	"edgeone-keyless-server/infrastructure/constant"
)

var chinaLocation *time.Location

func init() {
	var err error
	chinaLocation, err = time.LoadLocation(constant.TIME_LOCATION)
	if err != nil {
		fmt.Println("Error loading location:", err)
		chinaLocation = time.UTC
	}
}

func TimeFormat(now int64) string {
	if now < 0 {
		return ""
	}
	t := time.Unix(now, 0).In(chinaLocation)
	return t.Format(constant.TIME_FORMAT)
}
