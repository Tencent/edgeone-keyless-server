package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGetExeFilePath(t *testing.T) {
	// Create a temporary file
	currentPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Error getting current path:%v", err)
		return
	}
	tempFile, err := os.CreateTemp(filepath.Dir(currentPath), "test-executable")
	if err != nil {
		t.Fatalf("Error creating temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // Ensure the temporary file is deleted after the test
	t.Logf("file:%v", tempFile.Name())
	// Add the temporary file path to the PATH environment variable
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Dir(tempFile.Name()))
	defer os.Setenv("PATH", oldPath) // Ensure the PATH environment variable is restored after the test

	// Change the current working directory to the directory of the temporary file
	oldPwd, err := os.Getwd()
	t.Logf("oldPwd:%v", oldPwd)
	if err != nil {
		t.Fatalf("Error getting current working directory: %v", err)
	}
	err = os.Chdir(filepath.Dir(tempFile.Name()))
	if err != nil {
		t.Fatalf("Error changing working directory: %v", err)
	}
	defer os.Chdir(oldPwd) // Ensure the current working directory is restored after the test

	// Get the path of the executable file and check if it's correct
	path, err := GetExeFilePath()
	t.Logf("current path:%v", path)
	if err != nil {
		t.Fatalf("Error getting current path: %v", err)
	}
	if path != filepath.Dir(tempFile.Name()) {
		t.Errorf("Expected path %s, got %s", filepath.Dir(tempFile.Name()), path)
	}
}

func TestGetFileName(t *testing.T) {
	testCases := []struct {
		fileName     string
		expectedName string
	}{
		{"document.txt", "document"},
		{"archive.tar.gz", "archive.tar"},
		{"image.txt", "image"},
		{"", ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.fileName, func(t *testing.T) {
			result := GetFileName(testCase.fileName)
			if result != testCase.expectedName {
				t.Errorf("Expected '%s', got '%s'", testCase.expectedName, result)
			}
		})
	}
}

func TestGetKeys(t *testing.T) {
	tests := []struct {
		name string
		m    map[interface{}]interface{}
		want []interface{}
	}{
		{
			name: "Test with int keys",
			m: map[interface{}]interface{}{
				1: "one",
				2: "two",
				3: "three",
			},
			want: []interface{}{1, 2, 3},
		},
		{
			name: "Test with string keys",
			m: map[interface{}]interface{}{
				"a": "apple",
				"b": "banana",
				"c": "cherry",
			},
			want: []interface{}{"a", "b", "c"},
		},
		{
			name: "Test with empty map",
			m:    make(map[interface{}]interface{}),
			want: []interface{}{},
		},
		{
			name: "Test with mixed types keys",
			m: map[interface{}]interface{}{
				1:    "one",
				"a":  "apple",
				true: "boolean",
			},
			want: []interface{}{1, "a", true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetKeys(tt.m)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

type TestStruct struct {
	Field1 string `json:"field1"`
	Field2 int    `json:"field2"`
}

func TestPrintJsonLog(t *testing.T) {
	tests := []struct {
		name     string
		testData interface{}
		expected string
	}{
		{
			name: "Normal case",
			testData: TestStruct{
				Field1: "test",
				Field2: 123,
			},
			expected: `{"field1":"test","field2":123}`,
		},
		{
			name:     "Error case",
			testData: make(chan int),
			expected: "json: unsupported type: chan int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PrintJsonLog(tt.testData)
			if result != tt.expected {
				t.Errorf("Expected %s, but got %s", tt.expected, result)
			}
		})
	}
}

func TestTrimLeadingZeros(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"000123", "123"},   // 多个前导零
		{"0", ""},           // 单个零
		{"123", "123"},      // 无前导零
		{"", ""},            // 空字符串
		{"0000", ""},        // 全部是零
		{"0a0b0c", "a0b0c"}, // 中间有非零字符
	}

	for _, test := range tests {
		result := TrimLeadingZeros(test.input)
		if result != test.expected {
			t.Errorf("TrimLeadingZeros(%q) = %q; expected %q", test.input, result, test.expected)
		}
	}
}
