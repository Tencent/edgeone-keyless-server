// FILEPATH: /root/project/cert/infrastructure/utils/time_test.go
package utils // 假设你的函数在这个包中

import (
	"testing"
	"time"
)

func TestTimeFormat(t *testing.T) {
	// Normal case
	now := time.Now().Unix()
	expected := time.Now().Format("2006-01-02 15:04:05")
	if got := TimeFormat(now); got != expected {
		t.Errorf("TimeFormat(%d) = %s; want %s", now, got, expected)
	}

	// Edge case
	// For example: when the timestamp is 0
	if got := TimeFormat(0); got != "1970-01-01 08:00:00" {
		t.Errorf("TimeFormat(0) = %s; want '1970-01-01 08:00:00'", got)
	}

	// Abnormal case
	// For example: negative timestamp
	if got := TimeFormat(-1); got != "" { // Assume negative timestamp returns an empty string
		t.Errorf("TimeFormat(-1) = %s; want empty string", got)
	}
}
