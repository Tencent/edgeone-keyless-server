package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trpc.group/trpc-go/trpc-go/log"
)

// GetExeFilePath retrieves the directory of the executable file.
func GetExeFilePath() (string, error) {
	currentPath, err := os.Executable()
	if err != nil {
		log.Errorf("Error getting current path:%v", err)
		return "", err
	}
	// Get the absolute path of the current path
	absolutePath := filepath.Dir(currentPath)

	return absolutePath, nil
}

func GetCertKey(certSn, certIssuer string) string {
	// return certSn + "-" + certIssuer
	return certSn
}

// GetFileName retrieves the file name without the extension.
func GetFileName(fileName string) string {
	dotIndex := strings.LastIndex(fileName, ".")
	result := ""
	if dotIndex != -1 {
		result = fileName[:dotIndex]
		fmt.Println("Substring before the last dot:", result)
	} else {
		fmt.Println("No dot found in the input string")
	}
	return result
}

// PrintJsonLog prints the JSON representation of an object.
func PrintJsonLog(v any) string {
	vs, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(vs)
}

func GetKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// TrimLeadingZeros removes leading zeros from a string.
func TrimLeadingZeros(s string) string {
	// Check if the string is empty or the first character is '0'
	if len(s) > 0 && s[0] == '0' {
		// Use strings.TrimLeft to remove leading '0' characters
		s = strings.TrimLeft(s, "0")
	}
	return s
}
